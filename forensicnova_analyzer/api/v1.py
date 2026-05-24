"""
forensicnova_analyzer/api/v1.py — REST endpoints (v1).

Stage E2.2 introduced two read-only endpoints for acquisition listing.
Stage E2.5 (this revision) adds the async pipeline endpoints:

Read-only (E2.2):

  GET /api/v1/acquisitions
      List flattened summaries of every acquisition report in Swift.

  GET /api/v1/acquisitions/<acquisition_id>
      Full acquisition report + summary.

Async analysis pipeline (E2.5):

  POST /api/v1/analyses/<acquisition_id>
      Trigger an async analysis. Body JSON:
          {"analyzer": "noop"|"volatility",
           "preset":   "fast"|"full"|"custom"  (optional),
           "plugins":  ["windows.malfind", ...] (optional, custom only),
           "operator": "<name>" (optional, defaults to 'anonymous')}
      Response: 202 Accepted, {"job_id": "...", "status": "pending"}

  GET /api/v1/jobs/<job_id>
      Poll the status of an in-flight or terminated analysis job.

  GET /api/v1/jobs
      List all analyzer jobs, most recent first.

  GET /api/v1/analyses/<acquisition_id>
      List analyses already produced for a given acquisition_id.

  GET /api/v1/analyses/by-id/<analysis_id>
      Fetch a specific analysis JSON by its Swift object name.

  DELETE /api/v1/cache/<acquisition_id>
      Forcibly evict the cached dump for an acquisition. Idempotent.

Authentication is intentionally OFF in this revision. The system runs
on a single DevStack VM in development; keystonemiddleware will be
activated together with the Horizon dashboard wiring in a later commit.
"""
from __future__ import annotations

import json
import logging
import uuid

from flask import current_app, jsonify, request

from forensicnova_analyzer import swift
from forensicnova_analyzer.api import api_v1_bp
from forensicnova_analyzer.jobs_runner import (
    delete_acquisition_cache,
    start_analysis_job,
)

log = logging.getLogger("forensicnova_analyzer.api.v1")

# Whitelist of analyzers callable from the API. Adding a new analyzer
# requires both registering it here and wiring its class in the
# runner's _dispatch_analyzer (jobs_runner.py).
_KNOWN_ANALYZERS = {"noop", "volatility"}

# Preset whitelist per analyzer. None means "no preset validation"
# (e.g. noop ignores preset entirely). For volatility, only "fast" is
# accepted in E3; E4 will extend with "full" and "custom".
_SUPPORTED_PRESETS = {
    "noop":       None,
    "volatility": {"fast"},
}

# Role required to call any /api/v1/* endpoint. Same name as in the
# acquisition backend; granted by the DevStack plugin to dfir-tester.
_REQUIRED_ROLE = "forensic_analyst"


# ---------------------------------------------------------------------------
# Auth gate — runs before every /api/v1/* request.
# core_bp (/health, /version) is registered separately and not subject
# to this gate.
# ---------------------------------------------------------------------------

@api_v1_bp.before_request
def require_forensic_analyst():
    """Enforce Keystone authentication + role check on every API call.

    Trusts the X-Identity-Status header populated by
    keystonemiddleware.auth_token (which validated the X-Auth-Token
    header against Keystone before we got here). 'Confirmed' means
    the token was valid; anything else (typically 'Invalid' or
    missing entirely) is treated as unauthenticated.

    Role check is local: split HTTP_X_ROLES (comma-separated string)
    and look for forensic_analyst. The DevStack plugin grants this
    role to dfir-tester on the forensics project; if Horizon ever
    proxies a real human user, the same role must be granted there.

    On failure: short-circuit the request with 401 or 403 (no payload
    body parsing, no Swift hits). The corresponding endpoint code is
    never reached.
    """
    status = request.environ.get("HTTP_X_IDENTITY_STATUS")
    if status != "Confirmed":
        log.warning("auth rejected: identity_status=%r", status)
        return jsonify({
            "error":  "authentication_required",
            "detail": "provide a valid Keystone token via X-Auth-Token header",
        }), 401

    roles_header = request.environ.get("HTTP_X_ROLES", "")
    roles = [r.strip() for r in roles_header.split(",") if r.strip()]
    if _REQUIRED_ROLE not in roles:
        log.warning(
            "authz rejected: user=%s roles=%s",
            request.environ.get("HTTP_X_USER_NAME"), roles,
        )
        return jsonify({
            "error":         "insufficient_privileges",
            "detail":        f"{_REQUIRED_ROLE} role required",
            "current_roles": roles,
        }), 403


def _get_cfg():
    return current_app.config["FORENSICNOVA_ANALYZER"]


def _get_jobs():
    return current_app.config["JOB_MANAGER"]


# ---------------------------------------------------------------------------
# GET /api/v1/acquisitions — list summaries (E2.2)
# ---------------------------------------------------------------------------

@api_v1_bp.route("/acquisitions", methods=["GET"])
def list_acquisitions_endpoint():
    """List flattened summaries of every acquisition report in Swift."""
    cfg = _get_cfg()
    try:
        reports = swift.list_acquisitions(cfg)
    except Exception as exc:  # noqa: BLE001
        log.exception("list_acquisitions failed")
        return jsonify({"error": "internal_error", "message": str(exc)}), 500

    summaries: list[dict] = []
    skipped = 0
    for report in reports:
        try:
            summaries.append(swift.summarize_acquisition(report))
        except swift.UnsupportedReportSchema as exc:
            log.warning("skipping acquisition with unsupported schema: %s", exc)
            skipped += 1
        except (KeyError, ValueError, TypeError) as exc:
            log.warning(
                "skipping malformed acquisition (acquisition_id=%r): %s",
                report.get("acquisition_id"), exc,
            )
            skipped += 1

    log.info(
        "GET /api/v1/acquisitions -> %d summaries (%d skipped)",
        len(summaries), skipped,
    )
    return jsonify({
        "count":        len(summaries),
        "acquisitions": summaries,
        "skipped":      skipped,
    }), 200


# ---------------------------------------------------------------------------
# GET /api/v1/acquisitions/<acquisition_id> — single report + summary (E2.2)
# ---------------------------------------------------------------------------

@api_v1_bp.route("/acquisitions/<acquisition_id>", methods=["GET"])
def get_acquisition_endpoint(acquisition_id: str):
    """Return the full acquisition report and its flattened summary."""
    cfg = _get_cfg()

    try:
        report = swift.find_acquisition(acquisition_id, cfg)
    except Exception as exc:  # noqa: BLE001
        log.exception("find_acquisition(%s) failed", acquisition_id)
        return jsonify({"error": "internal_error", "message": str(exc)}), 500

    if report is None:
        log.info("GET /api/v1/acquisitions/%s -> 404", acquisition_id)
        return jsonify({
            "error":   "acquisition_not_found",
            "message": f"no acquisition with id {acquisition_id!r}",
        }), 404

    try:
        summary = swift.summarize_acquisition(report)
    except swift.UnsupportedReportSchema as exc:
        return jsonify({
            "error":          "unsupported_schema",
            "message":        str(exc),
            "schema_version": report.get("schema_version"),
        }), 422
    except (KeyError, ValueError, TypeError) as exc:
        log.exception("malformed report for %s", acquisition_id)
        return jsonify({
            "error":   "malformed_report",
            "message": str(exc),
        }), 422

    log.info("GET /api/v1/acquisitions/%s -> 200", acquisition_id)
    return jsonify({"summary": summary, "report": report}), 200


# ---------------------------------------------------------------------------
# POST /api/v1/analyses/<acquisition_id> — trigger async analysis (E2.5)
# ---------------------------------------------------------------------------

@api_v1_bp.route("/analyses/<acquisition_id>", methods=["POST"])
def trigger_analysis_endpoint(acquisition_id: str):
    """Start a new async analysis job for the given acquisition_id."""
    cfg = _get_cfg()
    jobs = _get_jobs()

    try:
        body = request.get_json(silent=True) or {}
    except Exception:  # noqa: BLE001
        body = {}

    analyzer_name = (body.get("analyzer") or "").strip().lower()
    if not analyzer_name:
        return jsonify({
            "error":   "missing_field",
            "message": "body field 'analyzer' is required",
        }), 400
    if analyzer_name not in _KNOWN_ANALYZERS:
        return jsonify({
            "error":   "unknown_analyzer",
            "message": (
                f"analyzer {analyzer_name!r} is not registered; "
                f"known: {sorted(_KNOWN_ANALYZERS)}"
            ),
        }), 400

    preset = body.get("preset")
    plugins = body.get("plugins")

    # Validate preset against the per-analyzer whitelist (E3: vol only
    # supports "fast"; E4 will widen). None preset is always accepted
    # — the runner picks a sensible default (e.g. "fast" for vol).
    supported = _SUPPORTED_PRESETS.get(analyzer_name)
    if preset is not None and supported is not None and preset not in supported:
        return jsonify({
            "error":   "unsupported_preset",
            "message": (
                f"analyzer={analyzer_name!r} does not support preset={preset!r}; "
                f"supported: {sorted(supported)}"
            ),
        }), 400

    # Operator identity comes from the Keystone-validated token, not
    # from the request body. before_request already ensured the token
    # is valid and has the forensic_analyst role, so HTTP_X_USER_NAME
    # is the audit-grade attribution. Falling back to 'anonymous'
    # only as a defensive default; in practice keystonemiddleware
    # always populates it.
    operator = request.environ.get("HTTP_X_USER_NAME") or "anonymous"

    if preset == "custom" and not plugins:
        return jsonify({
            "error":   "missing_field",
            "message": "preset='custom' requires non-empty 'plugins' list",
        }), 400
    if plugins and preset != "custom":
        return jsonify({
            "error":   "invalid_combination",
            "message": "'plugins' is only valid with preset='custom'",
        }), 400

    # Validate acquisition exists in Swift before spawning a worker.
    try:
        report = swift.find_acquisition(acquisition_id, cfg)
    except Exception as exc:  # noqa: BLE001
        log.exception("find_acquisition during POST failed")
        return jsonify({"error": "internal_error", "message": str(exc)}), 500
    if report is None:
        return jsonify({
            "error":   "acquisition_not_found",
            "message": f"no acquisition with id {acquisition_id!r}",
        }), 404

    job_id = str(uuid.uuid4())
    jobs.create_job(
        job_id=job_id,
        operator=operator,
        acquisition_id=acquisition_id,
        analyzer=analyzer_name,
        preset=preset,
        plugins=plugins,
    )
    start_analysis_job(
        cfg=cfg,
        jobs=jobs,
        job_id=job_id,
        acquisition_id=acquisition_id,
        analyzer_name=analyzer_name,
        operator=operator,
        preset=preset,
        plugins=plugins,
    )

    log.info(
        "POST /api/v1/analyses/%s -> 202 (job_id=%s, analyzer=%s, preset=%s)",
        acquisition_id, job_id, analyzer_name, preset,
    )
    return jsonify({
        "job_id":         job_id,
        "acquisition_id": acquisition_id,
        "analyzer":       analyzer_name,
        "preset":         preset,
        "plugins":        plugins,
        "operator":       operator,
        "status":         "pending",
        "poll_url":       f"/api/v1/jobs/{job_id}",
    }), 202


# ---------------------------------------------------------------------------
# GET /api/v1/jobs/<job_id> — poll job status (E2.5)
# ---------------------------------------------------------------------------

@api_v1_bp.route("/jobs/<job_id>", methods=["GET"])
def get_job_endpoint(job_id: str):
    """Return the full job record for the given job_id."""
    jobs = _get_jobs()
    record = jobs.get_job(job_id)
    if record is None:
        return jsonify({
            "error":   "job_not_found",
            "message": f"no job with id {job_id!r}",
        }), 404
    return jsonify(record), 200


# ---------------------------------------------------------------------------
# GET /api/v1/jobs — list all analyzer jobs (E2.5)
# ---------------------------------------------------------------------------

@api_v1_bp.route("/jobs", methods=["GET"])
def list_jobs_endpoint():
    """List analyzer jobs, most recent first (by started_at)."""
    jobs = _get_jobs()
    records = jobs.list_jobs()
    return jsonify({"count": len(records), "jobs": records}), 200


# ---------------------------------------------------------------------------
# GET /api/v1/analyses/<acquisition_id> — list analyses for one acquisition
# ---------------------------------------------------------------------------

@api_v1_bp.route("/analyses/<acquisition_id>", methods=["GET"])
def list_analyses_for_acquisition_endpoint(acquisition_id: str):
    """List the analysis-*.json objects already produced for an acquisition.

    Matches by object name prefix 'analysis-' followed by filtering on
    the acquisition_id substring. This avoids issuing one HEAD per
    object to read metadata.
    """
    cfg = _get_cfg()

    try:
        # Late import + private helpers reuse: justified by the
        # one-shot nature of this endpoint; the alternative would be
        # exposing a public swift.list_analyses() which we don't yet
        # need elsewhere.
        from forensicnova_analyzer.swift import _authenticate, _resolve_password
        import swiftclient
        password = _resolve_password(None)
        url, token = _authenticate(cfg, password)
        _h, objs = swiftclient.client.get_container(
            url=url,
            token=token,
            container=cfg.swift_container,
            prefix="analysis-",
        )
    except Exception as exc:  # noqa: BLE001
        log.exception("listing analyses for %s failed", acquisition_id)
        return jsonify({"error": "internal_error", "message": str(exc)}), 500

    matching: list[dict] = []
    for obj_info in objs:
        name = obj_info.get("name") or ""
        if acquisition_id not in name:
            continue
        matching.append({
            "analysis_id":   name,
            "size_bytes":    obj_info.get("bytes"),
            "last_modified": obj_info.get("last_modified"),
            "etag":          obj_info.get("hash"),
        })

    # Newest first — analysis_id embeds UTC timestamp, alphabetical
    # reverse equals chronological reverse.
    matching.sort(key=lambda x: x["analysis_id"], reverse=True)

    log.info(
        "GET /api/v1/analyses/%s -> %d analyses",
        acquisition_id, len(matching),
    )
    return jsonify({
        "acquisition_id": acquisition_id,
        "count":          len(matching),
        "analyses":       matching,
    }), 200


# ---------------------------------------------------------------------------
# GET /api/v1/analyses/by-id/<analysis_id> — fetch full analysis result
# ---------------------------------------------------------------------------

@api_v1_bp.route("/analyses/by-id/<path:analysis_id>", methods=["GET"])
def get_analysis_by_id_endpoint(analysis_id: str):
    """Fetch a specific analysis JSON by its Swift object name."""
    cfg = _get_cfg()

    try:
        from forensicnova_analyzer.swift import _authenticate, _resolve_password
        import swiftclient
        password = _resolve_password(None)
        url, token = _authenticate(cfg, password)
        _h, content = swiftclient.client.get_object(
            url=url,
            token=token,
            container=cfg.swift_container,
            name=analysis_id,
        )
    except Exception as exc:  # noqa: BLE001
        status_code = getattr(exc, "http_status", None)
        if status_code == 404:
            return jsonify({
                "error":   "analysis_not_found",
                "message": f"no analysis with id {analysis_id!r}",
            }), 404
        log.exception("get_analysis_by_id failed for %s", analysis_id)
        return jsonify({"error": "internal_error", "message": str(exc)}), 500

    try:
        payload = json.loads(content)
    except (ValueError, TypeError) as exc:
        return jsonify({
            "error":   "malformed_analysis",
            "message": str(exc),
        }), 500

    return jsonify(payload), 200


# ---------------------------------------------------------------------------
# DELETE /api/v1/cache/<acquisition_id> — evict cached dump (E2.5)
# ---------------------------------------------------------------------------

@api_v1_bp.route("/cache/<acquisition_id>", methods=["DELETE"])
def delete_cache_endpoint(acquisition_id: str):
    """Forcibly evict the cached dump for an acquisition. Idempotent."""
    cfg = _get_cfg()
    try:
        result = delete_acquisition_cache(acquisition_id, cfg)
    except Exception as exc:  # noqa: BLE001
        log.exception("delete cache for %s failed", acquisition_id)
        return jsonify({"error": "internal_error", "message": str(exc)}), 500

    log.info(
        "DELETE /api/v1/cache/%s -> %s",
        acquisition_id,
        "deleted" if result.get("deleted") else "noop",
    )
    return jsonify(result), 200
