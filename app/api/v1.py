"""ForensicNova v1 REST API — DFIR memory acquisition orchestrator.

Mounted at /api/v1 by the application factory (app/__init__.py).

Authentication contract:
  - keystonemiddleware (wired in app/__init__.py with delay_auth_decision=True)
    has already attempted to validate any X-Auth-Token in the incoming request.
  - It exposes the result via WSGI environ keys:
        HTTP_X_IDENTITY_STATUS  in {"Confirmed", "Invalid", missing}
        HTTP_X_USER_NAME        Keystone username (when Confirmed)
        HTTP_X_ROLES            comma-separated list of role names
  - The before_request hook below enforces:
        IDENTITY_STATUS == "Confirmed"        else 401
        "forensic_analyst" in X_ROLES         else 403

Endpoint:
  POST /api/v1/servers/<instance_id>/memory_acquire
      Acquire RAM of <instance_id>, hash, upload to Swift, return report.
      Synchronous: blocks until completion (FASE 4 prototype).
      Async with Celery is a thesis-scope improvement.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

import libvirt
from flask import Blueprint, current_app, jsonify, request

from app.forensics.acquirer import acquire_memory, secure_delete
from app.hashing.hasher import compute_hashes
from app.reports.chain_of_custody import ChainOfCustody
from app.reports.json_report import generate_report, serialize_report
from app.storage.swift_client import (
    IntegrityError,
    upload_dump,
    upload_json,
)

log = logging.getLogger("forensicnova.api.v1")

api_v1_bp = Blueprint("api_v1", __name__)


# ---------------------------------------------------------------------------
# Authentication / authorisation gate (runs before every v1 endpoint)
# ---------------------------------------------------------------------------

@api_v1_bp.before_request
def require_forensic_analyst():
    """Enforce Keystone token + forensic_analyst role on all v1 endpoints."""
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

    # OK — let the endpoint run.


# ---------------------------------------------------------------------------
# POST /servers/<instance_id>/memory_acquire — main DFIR orchestrator
# ---------------------------------------------------------------------------

@api_v1_bp.route(
    "/servers/<instance_id>/memory_acquire",
    methods=["POST"],
)
def memory_acquire(instance_id: str):
    """Acquire RAM of a Nova instance, hash it, upload to Swift, return report.

    :path instance_id: Nova instance UUID (resolved to libvirt domain).
    :returns: 201 + JSON summary on success, error JSON on failure.
    """
    cfg = current_app.config["FORENSICNOVA"]
    tool_version = current_app.config["VERSION"]
    operator = request.environ.get("HTTP_X_USER_NAME", "unknown")

    acquisition_id = str(uuid.uuid4())
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
        # -----------------------------------------------------------------
        # 1. Acquire RAM via libvirt (acquirer logs domain_lookup,
        #    virsh_dump_started, virsh_dump_completed events)
        # -----------------------------------------------------------------
        dump_path = acquire_memory(
            instance_id=instance_id,
            acquisition_id=acquisition_id,
            work_dir=cfg.work_dir,
            libvirt_uri=cfg.libvirt_uri,
            log_event=coc.log_event,
        )

        # Re-resolve domain name for the report (acquirer doesn't return it).
        domain_name = _lookup_domain_name(cfg.libvirt_uri, instance_id)

        # -----------------------------------------------------------------
        # 2. Hash the dump (streaming MD5 + SHA1)
        # -----------------------------------------------------------------
        hash_result = compute_hashes(dump_path, log_event=coc.log_event)

        # -----------------------------------------------------------------
        # 3. Upload dump to Swift with etag verification
        # -----------------------------------------------------------------
        swift_object_name = f"dump-{acquisition_id}.raw"
        swift_metadata = {
            "acquisition_id": acquisition_id,
            "operator":       operator,
            "instance_id":    instance_id,
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

        # -----------------------------------------------------------------
        # 4. Build the JSON report (embeds the full CoC trail)
        # -----------------------------------------------------------------
        report = generate_report(
            acquisition_id=acquisition_id,
            operator=operator,
            instance_id=instance_id,
            instance_name=domain_name,  # Nova display name lookup deferred
            domain_name=domain_name,
            hash_result=hash_result,
            swift_result=swift_result,
            tool_version=tool_version,
            timestamp=_utc_now_iso(),
            events=coc.events,
        )
        report_bytes = serialize_report(report)
        report_object_name = f"report-{acquisition_id}.json"
        report_swift_result = upload_json(
            json_bytes=report_bytes,
            object_name=report_object_name,
            cfg=cfg,
            log_event=coc.log_event,
        )

        # -----------------------------------------------------------------
        # 5. Secure delete local dump — ONLY if upload was etag-verified
        # -----------------------------------------------------------------
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

        # -----------------------------------------------------------------
        # 6. Respond with summary
        # -----------------------------------------------------------------
        log.info(
            "memory_acquire DONE: acq_id=%s size=%d md5=%s",
            acquisition_id, hash_result["size_bytes"], hash_result["md5"],
        )
        return jsonify({
            "acquisition_id":      acquisition_id,
            "status":              "completed",
            "instance_id":         instance_id,
            "domain_name":         domain_name,
            "operator":            operator,
            "size_bytes":          hash_result["size_bytes"],
            "md5":                 hash_result["md5"],
            "sha1":                hash_result["sha1"],
            "etag_verified":       swift_result["etag_verified"],
            "dump_swift_object":   swift_result["swift_object"],
            "report_swift_object": report_swift_result["swift_object"],
        }), 201

    # -----------------------------------------------------------------
    # Error handling: distinct status codes for distinct failure modes,
    # all events also captured in the CoC trail.
    # -----------------------------------------------------------------
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
# Helpers
# ---------------------------------------------------------------------------

def _lookup_domain_name(libvirt_uri: str, instance_id: str) -> str:
    """Resolve Nova instance UUID to libvirt domain name."""
    conn = libvirt.open(libvirt_uri)
    try:
        return conn.lookupByUUIDString(instance_id).name()
    finally:
        conn.close()


def _utc_now_iso() -> str:
    """ISO-8601 UTC timestamp with microsecond precision and 'Z' suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
