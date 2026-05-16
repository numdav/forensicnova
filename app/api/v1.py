"""ForensicNova v1 REST API — DFIR memory acquisition orchestrator.

Mounted at /api/v1 by the application factory (app/__init__.py).

Authentication contract:
  - keystonemiddleware (wired in app/__init__.py with delay_auth_decision=True)
    populates request.environ['HTTP_X_*'] with the validated identity.
  - The before_request hook enforces:
        IDENTITY_STATUS == "Confirmed"    else 401
        "forensic_analyst" in X_ROLES     else 403

Endpoints:
  POST /servers/<instance_id>/memory_acquire     — start acquisition (async, 202)
  GET  /servers/                                 — list all Nova instances
  GET  /jobs/                                    — list all async jobs
  GET  /jobs/<job_id>                            — status of one async job
  GET  /acquisitions/                            — list all acquisitions (summary)
  GET  /acquisitions/<acquisition_id>            — full report for one acquisition
  GET  /acquisitions/<acquisition_id>/dump       — download .raw dump (streaming)
  GET  /acquisitions/<acquisition_id>/report     — download .json report
  GET  /acquisitions/<acquisition_id>/report.pdf — download rendered PDF (on demand)

Async acquisition model (Feature 3.5):
  POST /servers/<id>/memory_acquire no longer blocks for the full
  pipeline. It creates a job record, spawns a daemon worker thread
  (app.jobs.runner.start_acquisition_job), and returns HTTP 202 with a
  job_id and a Location header pointing at GET /jobs/<job_id>. The
  caller polls that endpoint to follow phase/label/elapsed and, on
  completion, reads the embedded 'result' block (or fetches the full
  report via GET /acquisitions/<acquisition_id>).

  The acquisition_id is generated INSIDE the worker thread (not at
  request time), so the immediate 202 response carries acquisition_id:
  null; it becomes available on the job record a moment later.

Pipeline ordering (runner._run_acquisition):
  1. acquire_memory         (libvirt dump, chown, staging)
  2. compute_hashes         (MD5 + SHA1 streaming)
  3. nova_metadata.collect  (Nova + Glance + libvirt XML)
  4. upload_dump            (Swift PUT/SLO + etag verification)
  5. secure_delete          (shred -u local dump; only if etag verified)
  6. generate_report        (full CoC + self-referencing report.swift_object)
  7. upload_json            (report as second Swift object)

Object naming: dump-<sanitized_vm>-<YYYYMMDDTHHMMSSZ>.raw
               report-<sanitized_vm>-<YYYYMMDDTHHMMSSZ>.json
               (SLO segments live in '<container>_segments' as
                'dump-<sanitized_vm>-<YYYYMMDDTHHMMSSZ>.raw/seg-NNNN')
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone

import libvirt
from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    request,
    stream_with_context,
    url_for,
)

from app.forensics import nova_metadata
from app.reports.pdf_report import ForensicPdfReport
from app.storage.swift_client import (
    SwiftObjectNotFound,
    download_json,
    list_reports,
    stream_object,
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
# POST /servers/<instance_id>/memory_acquire   — async (HTTP 202)
# ---------------------------------------------------------------------------

@api_v1_bp.route(
    "/servers/<instance_id>/memory_acquire",
    methods=["POST"],
)
def memory_acquire(instance_id: str):
    """Start an asynchronous memory acquisition.

    Creates a job record, spawns the worker thread, and returns 202
    immediately. The heavy pipeline (dump, hash, upload, report) runs in
    the background; clients follow progress at GET /jobs/<job_id>.
    """
    cfg = current_app.config["FORENSICNOVA"]
    tool_version = current_app.config["VERSION"]
    jobs = current_app.config.get("FORENSICNOVA_JOBS")
    operator = request.environ.get("HTTP_X_USER_NAME", "unknown")

    if jobs is None:
        log.error("JobManager not initialised — cannot start acquisition")
        return jsonify(
            error="job_manager_unavailable",
            detail="the async job manager failed to initialise at startup; "
                   "inspect the service logs",
        ), 503

    # Best-effort instance name for nicer job listings; the authoritative
    # name is collected inside the worker via nova_metadata.collect().
    instance_name = None
    try:
        instance_name = _lookup_domain_name(cfg.libvirt_uri, instance_id)
    except Exception as exc:  # noqa: BLE001
        log.info(
            "could not pre-resolve domain name for %s (%s) — non-fatal",
            instance_id, exc,
        )

    job_id = str(uuid.uuid4())
    jobs.create_job(
        job_id=job_id,
        operator=operator,
        instance_id=instance_id,
        instance_name=instance_name,
    )

    # Import here to avoid a circular import at module load time
    # (runner imports helpers from this module).
    from app.jobs.runner import start_acquisition_job

    start_acquisition_job(
        cfg=cfg,
        tool_version=tool_version,
        jobs=jobs,
        job_id=job_id,
        instance_id=instance_id,
        operator=operator,
    )

    log.info(
        "memory_acquire ACCEPTED: instance=%s operator=%s job_id=%s",
        instance_id, operator, job_id,
    )

    location = url_for("api_v1.get_job", job_id=job_id)
    response = jsonify({
        "job_id":         job_id,
        "acquisition_id": None,  # generated inside the worker thread
        "instance_id":    instance_id,
        "instance_name":  instance_name,
        "operator":       operator,
        "status":         "pending",
        "phase":          "queued",
        "location":       location,
    })
    response.status_code = 202
    response.headers["Location"] = location
    return response


# ---------------------------------------------------------------------------
# GET /jobs/   — list async jobs
# ---------------------------------------------------------------------------

@api_v1_bp.route("/jobs/", methods=["GET"])
def list_jobs():
    operator = request.environ.get("HTTP_X_USER_NAME", "unknown")
    jobs = current_app.config.get("FORENSICNOVA_JOBS")

    if jobs is None:
        return jsonify(
            error="job_manager_unavailable",
            detail="the async job manager failed to initialise at startup",
        ), 503

    records = jobs.list_jobs()
    log.info("list_jobs: operator=%s returned %d jobs", operator, len(records))
    return jsonify({
        "count": len(records),
        "jobs":  records,
    }), 200


# ---------------------------------------------------------------------------
# GET /jobs/<job_id>   — single async job status
# ---------------------------------------------------------------------------

@api_v1_bp.route("/jobs/<job_id>", methods=["GET"])
def get_job(job_id: str):
    operator = request.environ.get("HTTP_X_USER_NAME", "unknown")
    jobs = current_app.config.get("FORENSICNOVA_JOBS")

    if jobs is None:
        return jsonify(
            error="job_manager_unavailable",
            detail="the async job manager failed to initialise at startup",
        ), 503

    record = jobs.get_job(job_id)
    if record is None:
        log.info("get_job: job_id=%s not found (operator=%s)", job_id, operator)
        return jsonify(
            error="not_found",
            detail=f"no job found with id {job_id}",
            job_id=job_id,
        ), 404

    log.debug(
        "get_job: job_id=%s status=%s phase=%s (operator=%s)",
        job_id, record.get("status"), record.get("phase"), operator,
    )
    return jsonify(record), 200


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
# GET /acquisitions/<acquisition_id>/report.pdf — rendered PDF on demand
# ---------------------------------------------------------------------------

@api_v1_bp.route("/acquisitions/<acquisition_id>/dump", methods=["GET"])
def download_acquisition_dump(acquisition_id: str):
    """Stream the raw memory dump to the client.

    For SLO objects, Swift transparently re-assembles the segments at
    GET time, so the analyst sees a single stream regardless of upload
    method.
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


@api_v1_bp.route("/acquisitions/<acquisition_id>/report.pdf", methods=["GET"])
def download_acquisition_report_pdf(acquisition_id: str):
    """Render and serve a PDF version of the JSON report on demand."""
    cfg = current_app.config["FORENSICNOVA"]
    operator = request.environ.get("HTTP_X_USER_NAME", "unknown")

    log.info(
        "download_pdf: acq_id=%s operator=%s",
        acquisition_id, operator,
    )

    report = _find_report_by_acquisition_id(acquisition_id, cfg)
    if report is None:
        return jsonify(
            error="not_found",
            detail=f"no acquisition found with id {acquisition_id}",
        ), 404

    report_block = report.get("report") or {}
    json_filename = (
        report_block.get("filename") or f"report-{acquisition_id}.json"
    )
    if json_filename.endswith(".json"):
        pdf_filename = json_filename[:-5] + ".pdf"
    else:
        pdf_filename = json_filename + ".pdf"

    try:
        pdf_bytes = ForensicPdfReport(report).render()
    except Exception as exc:
        log.exception("PDF rendering failed for acq=%s", acquisition_id)
        return jsonify(
            error="pdf_render_failed",
            detail=str(exc),
            acquisition_id=acquisition_id,
        ), 500

    log.info(
        "download_pdf: served %s (%d bytes) to operator=%s",
        pdf_filename, len(pdf_bytes), operator,
    )

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition":     f'attachment; filename="{pdf_filename}"',
            "Content-Length":          str(len(pdf_bytes)),
            "X-Content-Type-Options":  "nosniff",
        },
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_report_by_acquisition_id(acquisition_id: str, cfg):
    """Scan Swift report-*.json and return the parsed report matching the id."""
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

    slo_segments = dump.get("slo_segments") or []

    return {
        "acquisition_id":      report.get("acquisition_id"),
        "operator":            report.get("operator"),
        "vm_name":             instance.get("name"),
        "instance_id":         instance.get("id"),
        "domain_name":         instance.get("domain"),
        "started_at":          timestamps.get("started_at"),
        "completed_at":        timestamps.get("completed_at"),
        "duration_seconds":    timestamps.get("duration_seconds"),
        "size_bytes":          dump.get("size_bytes"),
        "md5":                 dump.get("md5"),
        "sha1":                dump.get("sha1"),
        "etag_verified":       dump.get("etag_verified"),
        "upload_method":       dump.get("upload_method") or "single_put",
        "slo_segments_count":  len(slo_segments),
        "swift_dump":          dump.get("swift_object"),
        "swift_report":        report_blk.get("swift_object"),
        "report_object":       object_name,
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
