"""ForensicNova v1 REST API — DFIR memory acquisition orchestrator.

Mounted at /api/v1 by the application factory (app/__init__.py).

Authentication contract:
  - keystonemiddleware (wired in app/__init__.py with delay_auth_decision=True)
    populates request.environ['HTTP_X_*'] with the validated identity.
  - The before_request hook enforces:
        IDENTITY_STATUS == "Confirmed"    else 401
        "forensic_analyst" in X_ROLES     else 403

Pipeline ordering (FASE 4 final):
  1. acquire_memory         (libvirt dump, chown, staging)
  2. compute_hashes         (MD5 + SHA1 streaming)
  3. nova_metadata.collect  (Nova + Glance + libvirt XML — drives VM-naming)
  4. upload_dump            (Swift PUT + etag verification)
  5. secure_delete          (shred -u local dump; only if etag verified)
  6. generate_report        (full CoC + self-referencing report.swift_object)
  7. upload_json            (report as second Swift object)

Object naming: dump-<sanitized_vm>-<YYYYMMDDTHHMMSSZ>.raw
               report-<sanitized_vm>-<YYYYMMDDTHHMMSSZ>.json
"""
from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone

import libvirt
from flask import Blueprint, current_app, jsonify, request

from app.forensics.acquirer import acquire_memory, secure_delete
from app.forensics import nova_metadata
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
        # 1. Acquire RAM via libvirt
        dump_path = acquire_memory(
            instance_id=instance_id,
            acquisition_id=acquisition_id,
            work_dir=cfg.work_dir,
            libvirt_uri=cfg.libvirt_uri,
            log_event=coc.log_event,
        )
        domain_name = _lookup_domain_name(cfg.libvirt_uri, instance_id)

        # 2. Hash dump (streaming MD5 + SHA1)
        hash_result = compute_hashes(dump_path, log_event=coc.log_event)

        # 3. Collect OpenStack-side metadata (provides VM name for naming)
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

        # 4. Upload dump to Swift with etag verification
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

        # 5. Secure-delete local dump — ONLY if etag verified.
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

        # 6. Generate JSON report (with self-referencing report block)
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

        # 7. Upload report
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
# Helpers
# ---------------------------------------------------------------------------

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
