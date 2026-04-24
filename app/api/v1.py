"""ForensicNova v1 REST API — DFIR memory acquisition orchestrator.

Mounted at /api/v1 by the application factory (app/__init__.py).

Authentication contract:
  - keystonemiddleware (wired in app/__init__.py with delay_auth_decision=True)
    populates request.environ['HTTP_X_*'] with the validated identity.
  - The before_request hook enforces:
        IDENTITY_STATUS == "Confirmed"    else 401
        "forensic_analyst" in X_ROLES     else 403

Endpoints:
  POST /servers/<instance_id>/memory_acquire   — trigger acquisition pipeline
  GET  /servers/                               — list all Nova instances
  GET  /acquisitions/                          — list all acquisitions (summary)
  GET  /acquisitions/<acquisition_id>          — full report for one acquisition
  GET  /acquisitions/<acquisition_id>/dump     — download .raw dump (streaming)
  GET  /acquisitions/<acquisition_id>/report   — download .json report

Pipeline ordering (FASE 4 final):
  1. acquire_memory         (libvirt dump, chown, staging)
  2. compute_hashes         (MD5 + SHA1 streaming)
  3. nova_metadata.collect  (Nova + Glance + libvirt XML)
  4. upload_dump            (Swift PUT + etag verification)
  5. secure_delete          (shred -u local dump; only if etag verified)
  6. generate_report        (full CoC + self-referencing report.swift_object)
  7. upload_json            (report as second Swift object)

Object naming: dump-<sanitized_vm>-<YYYYMMDDTHHMMSSZ>.raw
               report-<sanitized_vm>-<YYYYMMDDTHHMMSSZ>.json
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone

import libvirt
from flask import Blueprint, Response, current_app, jsonify, request, stream_with_context

from app.forensics.acquirer import acquire_memory, secure_delete
from app.forensics import nova_metadata
from app.hashing.hasher import compute_hashes
from app.reports.chain_of_custody import ChainOfCustody
from app.reports.json_report import generate_report, serialize_report
from app.storage.swift_client import (
    IntegrityError,
    SwiftObjectNotFound,
    download_json,
    list_reports,
    stream_object,
    upload_dump,
    upload_json,
)

log = logging.getLogger("forensicnova.api.v1")

api_v1_bp = Blueprint("api_v1", __name__)

_VM_NAME_MAX_LEN = 64


# ---------------------------------------------------------------------------
# Auth gate
# ---------------------------------------------------------------------------

@api_v1_bp.before_request
def require_forensic_analyst():
    status = request.environ.get("HTTP_X_IDENTITY_STATUS")
    if status != "Confirmed":
        log.warning("auth rejected: identity_status=%r", status)
        return jsonify(
            error="authentication_required",
            detail="provide a valid Keystone token via X-Auth-Token header",
        ), 401

    roles_header = request.environ.get("HTTP_X_ROLES", "")
    roles = [r.strip() for r in roles_header.split(",") if r.strip()]
    if "forensic_analyst" not in roles:
        log.warning(
            "authz rejected: user=%s roles=%s",
            request.environ.get("HTTP_X_USER_NAME"), roles,
        )
        return jsonify(
            error="insufficient_privileges",
            detail="forensic_analyst role required",
            current_roles=roles,
        ), 403


# ---------------------------------------------------------------------------
# POST /servers/<instance_id>/memory_acquire
# ---------------------------------------------------------------------------

@api_v1_bp.route(
    "/servers/<instance_id>/memory_acquire",
    methods=["POST"],
)
def memory_acquire(instance_id: str):
    cfg = current_app.config["FORENSICNOVA"]
    tool_version = current_app.config["VERSION"]
    operator = request.environ.get("HTTP_X_USER_NAME", "unknown")

    acquisition_id = str(uuid.uuid4())
    started_at = _utc_now_iso()
    timestamp_compact = _utc_now_compact()

    coc = ChainOfCustody(
        acquisition_id=acquisition_id,
        operator=operator,
        log_dir=cfg.log_dir,
    )

    log.info(
        "memory_acquire START: instance=%s operator=%s acq_id=%s",
        instance_id, operator, acquisition_id,
    )
    coc.log_event("api_request_received", {
        "instance_id":    instance_id,
        "endpoint":       "memory_acquire",
        "client_address": request.remote_addr,
    })

    try:
        dump_path = acquire_memory(
            instance_id=instance_id,
            acquisition_id=acquisition_id,
            work_dir=cfg.work_dir,
            libvirt_uri=cfg.libvirt_uri,
            log_event=coc.log_event,
        )
        domain_name = _lookup_domain_name(cfg.libvirt_uri, instance_id)

        hash_result = compute_hashes(dump_path, log_event=coc.log_event)

        target_system = nova_metadata.collect(
            instance_id=instance_id,
            domain_name=domain_name,
            libvirt_uri=cfg.libvirt_uri,
            cfg=cfg,
        )

        vm_name_raw = (
            (target_system.get("nova") or {}).get("name")
            or domain_name
            or "unknown"
        )
        vm_name_safe = _sanitize_vm_name(vm_name_raw)

        swift_object_name  = f"dump-{vm_name_safe}-{timestamp_compact}.raw"
        report_object_name = f"report-{vm_name_safe}-{timestamp_compact}.json"

        swift_metadata = {
            "acquisition_id": acquisition_id,
            "operator":       operator,
            "instance_id":    instance_id,
            "instance_name":  vm_name_raw,
            "domain_name":    domain_name,
            "md5":            hash_result["md5"],
            "sha1":           hash_result["sha1"],
            "tool_version":   tool_version,
            "timestamp":      _utc_now_iso(),
        }
        swift_result = upload_dump(
            local_path=dump_path,
            object_name=swift_object_name,
            metadata=swift_metadata,
            cfg=cfg,
            log_event=coc.log_event,
        )

        if swift_result["etag_verified"]:
            secure_delete(dump_path)
            coc.log_event("local_dump_secure_deleted", {
                "path": str(dump_path),
            })
        else:
            log.warning(
                "etag NOT verified — local dump preserved at %s", dump_path,
            )
            coc.log_event("local_dump_preserved", {
                "path":   str(dump_path),
                "reason": "etag_not_verified",
            })

        completed_at = _utc_now_iso()
        report = generate_report(
            acquisition_id=acquisition_id,
            operator=operator,
            instance_id=instance_id,
            instance_name=vm_name_raw,
            domain_name=domain_name,
            hash_result=hash_result,
            swift_result=swift_result,
            tool_version=tool_version,
            timestamp=completed_at,
            started_at=started_at,
            target_system=target_system,
            report_object_name=report_object_name,
            container=cfg.swift_container,
            events=list(coc.events),
        )
        report_bytes = serialize_report(report)

        report_swift_result = upload_json(
            json_bytes=report_bytes,
            object_name=report_object_name,
            cfg=cfg,
            log_event=coc.log_event,
        )

        log.info(
            "memory_acquire DONE: acq_id=%s vm=%s size=%d md5=%s",
            acquisition_id, vm_name_raw, hash_result["size_bytes"], hash_result["md5"],
        )
        return jsonify({
            "acquisition_id":      acquisition_id,
            "status":              "completed",
            "instance_id":         instance_id,
            "instance_name":       vm_name_raw,
            "domain_name":         domain_name,
            "operator":            operator,
            "started_at":          started_at,
            "completed_at":        completed_at,
            "size_bytes":          hash_result["size_bytes"],
            "md5":                 hash_result["md5"],
            "sha1":                hash_result["sha1"],
            "etag_verified":       swift_result["etag_verified"],
            "dump_swift_object":   swift_result["swift_object"],
            "report_swift_object": report_swift_result["swift_object"],
        }), 201

    except IntegrityError as exc:
        log.error("integrity failure acq=%s: %s", acquisition_id, exc)
        coc.log_event("acquisition_failed", {
            "reason": "integrity_failure",
            "error":  str(exc),
        })
        return jsonify(
            error="integrity_verification_failed",
            detail=str(exc),
            acquisition_id=acquisition_id,
            note="local dump preserved for forensic debugging",
        ), 500

    except libvirt.libvirtError as exc:
        log.error("libvirt error acq=%s: %s", acquisition_id, exc)
        coc.log_event("acquisition_failed", {
            "reason": "libvirt_error",
            "error":  str(exc),
        })
        return jsonify(
            error="libvirt_error",
            detail=str(exc),
            acquisition_id=acquisition_id,
        ), 502

    except (FileNotFoundError, PermissionError, OSError) as exc:
        log.error("filesystem error acq=%s: %s", acquisition_id, exc)
        coc.log_event("acquisition_failed", {
            "reason": "filesystem_error",
            "error":  str(exc),
        })
        return jsonify(
            error="filesystem_error",
            detail=str(exc),
            acquisition_id=acquisition_id,
        ), 500

    except Exception as exc:
        log.exception("unexpected error acq=%s", acquisition_id)
        coc.log_event("acquisition_failed", {
            "reason": "unexpected",
            "error":  str(exc),
        })
        return jsonify(
            error="internal_server_error",
            detail=str(exc),
            acquisition_id=acquisition_id,
        ), 500


# ---------------------------------------------------------------------------
# GET /servers/   — list Nova instances
# ---------------------------------------------------------------------------

@api_v1_bp.route("/servers/", methods=["GET"])
def list_servers():
    cfg = current_app.config["FORENSICNOVA"]
    operator = request.environ.get("HTTP_X_USER_NAME", "unknown")

    log.info("list_servers: operator=%s", operator)

    try:
        servers = nova_metadata.list_all_servers(cfg)
    except Exception as exc:  # noqa: BLE001
        log.exception("list_all_servers failed")
        return jsonify(
            error="nova_list_failed",
            detail=str(exc),
        ), 502

    return jsonify({
        "count":   len(servers),
        "servers": servers,
    }), 200


# ---------------------------------------------------------------------------
# GET /acquisitions/   — list summary
# ---------------------------------------------------------------------------

@api_v1_bp.route("/acquisitions/", methods=["GET"])
def list_acquisitions():
    cfg = current_app.config["FORENSICNOVA"]
    operator = request.environ.get("HTTP_X_USER_NAME", "unknown")

    log.info("list_acquisitions: operator=%s", operator)

    try:
        report_names = list_reports(cfg)
    except Exception as exc:
        log.exception("list_reports failed")
        return jsonify(
            error="swift_list_failed",
            detail=str(exc),
        ), 502

    summaries: list[dict] = []
    for name in report_names:
        try:
            raw = download_json(name, cfg)
            report = json.loads(raw.decode("utf-8"))
            summaries.append(_build_summary(report, name))
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "skipping unreadable report object %s: %s", name, exc,
            )
            continue

    summaries.sort(
        key=lambda s: s.get("completed_at") or "",
        reverse=True,
    )

    log.info(
        "list_acquisitions: returned %d summaries (from %d objects)",
        len(summaries), len(report_names),
    )
    return jsonify({
        "count":        len(summaries),
        "acquisitions": summaries,
    }), 200


# ---------------------------------------------------------------------------
# GET /acquisitions/<acquisition_id>   — full report
# ---------------------------------------------------------------------------

@api_v1_bp.route("/acquisitions/<acquisition_id>", methods=["GET"])
def get_acquisition(acquisition_id: str):
    cfg = current_app.config["FORENSICNOVA"]
    operator = request.environ.get("HTTP_X_USER_NAME", "unknown")

    log.info(
        "get_acquisition: acq_id=%s operator=%s",
        acquisition_id, operator,
    )

    report = _find_report_by_acquisition_id(acquisition_id, cfg)
    if report is None:
        return jsonify(
            error="not_found",
            detail=f"no acquisition found with id {acquisition_id}",
            acquisition_id=acquisition_id,
        ), 404

    return jsonify(report), 200


# ---------------------------------------------------------------------------
# GET /acquisitions/<acquisition_id>/dump     — streaming download .raw
# GET /acquisitions/<acquisition_id>/report   — download .json
# ---------------------------------------------------------------------------

@api_v1_bp.route("/acquisitions/<acquisition_id>/dump", methods=["GET"])
def download_acquisition_dump(acquisition_id: str):
    """Stream the raw memory dump to the client.

    The body is streamed chunk-by-chunk directly from Swift through Flask —
    never fully loaded into the API process's RAM.  For a 4 GB Windows
    dump this means constant ~1 MB memory usage regardless of file size.
    """
    cfg = current_app.config["FORENSICNOVA"]
    operator = request.environ.get("HTTP_X_USER_NAME", "unknown")

    log.info(
        "download_dump: acq_id=%s operator=%s",
        acquisition_id, operator,
    )

    report = _find_report_by_acquisition_id(acquisition_id, cfg)
    if report is None:
        return jsonify(
            error="not_found",
            detail=f"no acquisition found with id {acquisition_id}",
        ), 404

    swift_object = (report.get("dump") or {}).get("swift_object") or ""
    object_name = _extract_object_name(swift_object)
    if not object_name:
        log.error("malformed swift_object field in report: %r", swift_object)
        return jsonify(
            error="report_malformed",
            detail="report does not contain a valid dump.swift_object",
        ), 500

    try:
        headers, body_iter = stream_object(object_name, cfg)
    except SwiftObjectNotFound:
        return jsonify(
            error="not_found",
            detail=f"dump object no longer in Swift: {object_name}",
        ), 404
    except Exception as exc:  # noqa: BLE001
        log.exception("stream_object failed for %s", object_name)
        return jsonify(
            error="swift_stream_failed",
            detail=str(exc),
        ), 502

    size = headers.get("content-length", "")
    log.info(
        "download_dump: streaming %s (%s bytes) to operator=%s",
        object_name, size, operator,
    )

    return Response(
        stream_with_context(body_iter),
        mimetype="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{object_name}"',
            "Content-Length":      size,
            "X-Content-Type-Options": "nosniff",
        },
    )


@api_v1_bp.route("/acquisitions/<acquisition_id>/report", methods=["GET"])
def download_acquisition_report(acquisition_id: str):
    """Download the JSON report as an attachment (not rendered inline)."""
    cfg = current_app.config["FORENSICNOVA"]
    operator = request.environ.get("HTTP_X_USER_NAME", "unknown")

    log.info(
        "download_report: acq_id=%s operator=%s",
        acquisition_id, operator,
    )

    report = _find_report_by_acquisition_id(acquisition_id, cfg)
    if report is None:
        return jsonify(
            error="not_found",
            detail=f"no acquisition found with id {acquisition_id}",
        ), 404

    # Object name is either in the self-referencing report block (preferred)
    # or derivable via full-scan (we already have it from the lookup, but
    # the lookup doesn't expose the name).  Use the self-ref.
    report_block = report.get("report") or {}
    object_name = report_block.get("filename") or _extract_object_name(
        report_block.get("swift_object", "")
    )
    if not object_name:
        return jsonify(
            error="report_malformed",
            detail="report does not contain a valid self-reference filename",
        ), 500

    body_bytes = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")

    return Response(
        body_bytes,
        mimetype="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{object_name}"',
            "Content-Length":      str(len(body_bytes)),
            "X-Content-Type-Options": "nosniff",
        },
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_report_by_acquisition_id(acquisition_id: str, cfg):
    """Scan Swift report-*.json and return the parsed report matching the id.

    Shared between GET /acquisitions/<id>, /dump, and /report.  See the
    thesis optimization note in the original list_acquisitions docstring.
    """
    try:
        report_names = list_reports(cfg)
    except Exception:
        log.exception("list_reports failed")
        raise

    for name in report_names:
        try:
            raw = download_json(name, cfg)
            report = json.loads(raw.decode("utf-8"))
        except SwiftObjectNotFound:
            continue
        except Exception as exc:  # noqa: BLE001
            log.warning("skipping unreadable report %s: %s", name, exc)
            continue

        if report.get("acquisition_id") == acquisition_id:
            log.debug("found report in %s for acq=%s", name, acquisition_id)
            return report

    log.info(
        "no report found for acq=%s (scanned %d objects)",
        acquisition_id, len(report_names),
    )
    return None


def _extract_object_name(swift_object_path: str) -> str:
    """Extract the object name from a 'container/object' path.

    Swift paths in the report look like 'forensics/dump-vm-ts.raw'.
    We use the object name (no container) for swiftclient calls.
    """
    if not swift_object_path:
        return ""
    if "/" in swift_object_path:
        return swift_object_path.split("/", 1)[1]
    return swift_object_path


def _build_summary(report: dict, object_name: str) -> dict:
    """Project a full report JSON onto a compact summary dict for listing."""
    dump       = report.get("dump", {}) or {}
    instance   = report.get("instance", {}) or {}
    timestamps = report.get("timestamps", {}) or {}
    report_blk = report.get("report", {}) or {}

    return {
        "acquisition_id":   report.get("acquisition_id"),
        "operator":         report.get("operator"),
        "vm_name":          instance.get("name"),
        "instance_id":      instance.get("id"),
        "domain_name":      instance.get("domain"),
        "started_at":       timestamps.get("started_at"),
        "completed_at":     timestamps.get("completed_at"),
        "duration_seconds": timestamps.get("duration_seconds"),
        "size_bytes":       dump.get("size_bytes"),
        "md5":              dump.get("md5"),
        "sha1":             dump.get("sha1"),
        "etag_verified":    dump.get("etag_verified"),
        "swift_dump":       dump.get("swift_object"),
        "swift_report":     report_blk.get("swift_object"),
        "report_object":    object_name,
    }


def _lookup_domain_name(libvirt_uri: str, instance_id: str) -> str:
    conn = libvirt.open(libvirt_uri)
    try:
        return conn.lookupByUUIDString(instance_id).name()
    finally:
        conn.close()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _utc_now_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _sanitize_vm_name(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9-]", "_", name or "")
    cleaned = re.sub(r"_+", "_", cleaned).strip("_-")
    cleaned = cleaned[:_VM_NAME_MAX_LEN]
    return cleaned or "unknown"
