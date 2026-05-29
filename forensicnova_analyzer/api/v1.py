"""
forensicnova_analyzer/api/v1.py — REST endpoints (v1).

Stage E2.2 introduced two read-only endpoints for acquisition listing.
Stage E2.5 added the async pipeline endpoints. This revision removes
the no-op analyzer from the public API surface: the NoOpAnalyzer class
remains in the codebase (forensicnova_analyzer/analyzers/noop.py) as a
reference implementation of the analyzer protocol — useful when a
future analyzer is added (e.g. MispEnricher) and a known-good baseline
for the coherence-check pipeline is helpful. It is simply no longer
exposed as a selectable choice in the UI or as a callable analyzer
name via POST /api/v1/analyses.

Read-only (E2.2):

  GET /api/v1/acquisitions
      List flattened summaries of every acquisition report in Swift.

  GET /api/v1/acquisitions/<acquisition_id>
      Full acquisition report + summary.

Async analysis pipeline:

  POST /api/v1/analyses/<acquisition_id>
      Trigger an async analysis. Body JSON:
          {"analyzer": "volatility",
           "preset":   "fast"|"full"|"custom"  (required for volatility),
           "plugins":  ["windows.malfind", ...] (required when preset=custom),
           "operator": "<name>" (optional, defaults to Keystone X-User-Name)}
      Response: 202 Accepted, {"job_id": "...", "status": "pending"}

  GET /api/v1/jobs/<job_id>
      Poll the status of an in-flight or terminated analysis job.

  GET /api/v1/jobs
      List all analyzer jobs, most recent first.

  GET /api/v1/plugins
      Discover available analyzers, presets, plugin whitelist.

  GET /api/v1/analyses/<acquisition_id>
      List analyses already produced for a given acquisition_id.

  GET /api/v1/analyses/by-id/<analysis_id>
      Fetch a specific analysis JSON by its Swift object name.

  DELETE /api/v1/cache/<acquisition_id>
      Forcibly evict the cached dump for an acquisition. Idempotent.

All /api/v1/* endpoints require a Keystone-validated token (via
keystonemiddleware) plus the forensic_analyst role. /health and
/version on core_bp are exempt and remain unauthenticated.
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

# Whitelist of analyzers callable from the API. Currently only the
# Volatility 3 analyzer is exposed; the NoOpAnalyzer remains in the
# codebase as a reference but is intentionally not advertised, to
# avoid presenting the user with a meaningless choice ("run an
# analyzer that does no analysis"). Adding a new analyzer requires
# both registering it here and wiring its class in the runner's
# _dispatch_analyzer (jobs_runner.py).
_KNOWN_ANALYZERS = {"volatility"}

# Preset whitelist per analyzer. Volatility supports the three preset
# tiers; custom requires an explicit plugins list.
_SUPPORTED_PRESETS = {
    "volatility": {"fast", "full", "custom"},
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
# GET /api/v1/acquisitions/<acquisition_id> — single report + summary
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
# POST /api/v1/analyses/<acquisition_id> — trigger async analysis
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

    # Validate preset against the per-analyzer whitelist.
    supported = _SUPPORTED_PRESETS.get(analyzer_name)
    if preset is not None and supported is not None and preset not in supported:
        return jsonify({
            "error":   "unsupported_preset",
            "message": (
                f"analyzer={analyzer_name!r} does not support preset={preset!r}; "
                f"supported: {sorted(supported)}"
            ),
        }), 400

    # Pre-validate custom plugin list at API level (immediate 400),
    # so the user gets feedback before a job is created and the
    # asynchronous worker fails. Linux is currently out of scope so
    # we only check against the Windows whitelist.
    if analyzer_name == "volatility" and preset == "custom" and plugins:
        from forensicnova_analyzer.analyzers.volatility import (
            PLUGIN_WHITELIST_WINDOWS,
        )
        rejected = [p for p in plugins if p not in PLUGIN_WHITELIST_WINDOWS]
        if rejected:
            return jsonify({
                "error":   "unknown_plugins",
                "message": (
                    "Some plugins are not in the whitelist. Plugins producing "
                    "binary file output (dumpfiles, pedump, strings) and "
                    "deprecated FQN aliases are excluded by design."
                ),
                "rejected_plugins": rejected,
                "hint": (
                    "Use FQN format (e.g. 'windows.malware.malfind.Malfind'). "
                    "See /api/v1/plugins for the full whitelist."
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
# GET /api/v1/jobs/<job_id> — poll job status
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
# DELETE /api/v1/jobs/<job_id> — remove a job + cascade Swift analysis JSON
# ---------------------------------------------------------------------------
#
# Cleanup utility primarily intended for the dashboard's Delete action
# in the Analyses table. Two responsibilities, both idempotent:
#
#   1. If the job had produced a Swift analysis-*.json (i.e. status was
#      'completed' before the delete), remove it from the Swift
#      'forensics' container. Missing object = no-op (200, deleted=false).
#
#   2. Remove the job's persisted record from the analyzer's local jobs/
#      directory. Missing job file = no-op (200, deleted=false).
#
# Both legs are reported separately in the response so the operator can
# tell whether the cascade actually had something to delete on Swift.
# A common case post-unstack/stack: the job file lingers but the Swift
# object is already gone (container was rebuilt). The endpoint returns
# 200 with cascade_swift.deleted=false and removed_job=true, which the
# dashboard surfaces as a benign "cleaned up orphan job".
#
# Authorization: forensic_analyst role required (enforced by the
# before_request hook). No separate admin role: the lab's analyst is
# expected to manage their own analyses lifecycle. Production
# hardening would gate this behind an additional 'admin' role.

@api_v1_bp.route("/jobs/<job_id>", methods=["DELETE"])
def delete_job_endpoint(job_id: str):
    """Delete an analyzer job + (if any) the associated Swift analysis JSON.

    Returns 200 with a breakdown of what was actually removed. Never
    raises 404 — a missing job is reported as removed_job=false.
    """
    cfg = _get_cfg()
    jobs = _get_jobs()

    # Read the job FIRST (before deleting the local file) so we know
    # the analysis_id to cascade-delete from Swift, and so we can report
    # back any acquisition_id / analyzer metadata the dashboard might
    # display in a flash message.
    record = jobs.get_job(job_id)
    job_status = (record or {}).get("status")
    job_analyzer = (record or {}).get("analyzer")
    analysis_id = (record or {}).get("analysis_id")
    acquisition_id = (record or {}).get("acquisition_id")

    # --- Leg 1: Swift cascade ---
    cascade_result: dict
    if analysis_id:
        try:
            cascade_result = swift.delete_analysis_object(analysis_id, cfg)
        except Exception as exc:  # noqa: BLE001
            log.exception(
                "delete_job: Swift cascade failed for job=%s analysis_id=%s",
                job_id, analysis_id,
            )
            # Swift failure does NOT abort the job-file delete: the
            # operator's stated intent is "get rid of this job",
            # leaving a stale job pointing at an unreachable Swift
            # object would defeat the purpose. We still report the
            # failure so it's visible.
            cascade_result = {
                "object_name": analysis_id,
                "deleted":     False,
                "status":      "error",
                "error":       str(exc),
            }
    else:
        cascade_result = {
            "object_name": None,
            "deleted":     False,
            "status":      "no_analysis_id",
            "error":       None,
        }

    # --- Leg 2: local job file delete ---
    try:
        local_result = jobs.delete_job(job_id)
    except Exception as exc:  # noqa: BLE001
        log.exception("delete_job: local file delete failed for job=%s", job_id)
        return jsonify({
            "error":          "internal_error",
            "message":        f"could not delete local job file: {exc}",
            "cascade_swift":  cascade_result,
        }), 500

    response_body = {
        "job_id":         job_id,
        "removed_job":    bool(local_result.get("deleted")),
        "previous_status": job_status,
        "analyzer":       job_analyzer,
        "acquisition_id": acquisition_id,
        "analysis_id":    analysis_id,
        "cascade_swift":  cascade_result,
    }
    log.info(
        "DELETE /api/v1/jobs/%s -> removed_job=%s swift=%s (was status=%s)",
        job_id, response_body["removed_job"],
        cascade_result.get("status"), job_status,
    )
    return jsonify(response_body), 200


# ---------------------------------------------------------------------------
# GET /api/v1/jobs — list all analyzer jobs
# ---------------------------------------------------------------------------

@api_v1_bp.route("/jobs", methods=["GET"])
def list_jobs_endpoint():
    """List analyzer jobs, most recent first (by started_at)."""
    jobs = _get_jobs()
    records = jobs.list_jobs()
    return jsonify({"count": len(records), "jobs": records}), 200


# ---------------------------------------------------------------------------
# GET /api/v1/plugins — discover available presets + whitelist
# ---------------------------------------------------------------------------

@api_v1_bp.route("/plugins", methods=["GET"])
def list_plugins_endpoint():
    """Discover available analyzers, presets, and custom plugin whitelist.

    Used by clients (Horizon dashboard, scripted callers) to populate
    selection UIs and validate plugin names before submitting a custom
    analysis request.

    Returns a structured catalogue:
        {
          "analyzers":   ["volatility"],
          "volatility": {
            "presets": {
              "fast": {"windows": [...], "linux": []},
              "full": {"windows": [...], "linux": []},
              "custom": "see plugin_whitelist"
            },
            "plugin_whitelist": {
              "windows": [...],   # sorted FQN list
              "linux":   []       # Linux out of scope in this release
            }
          }
        }
    """
    from forensicnova_analyzer.analyzers.volatility import (
        PRESET_FAST_WINDOWS, PRESET_FAST_LINUX,
        PRESET_FULL_WINDOWS, PRESET_FULL_LINUX,
        PLUGIN_WHITELIST_WINDOWS, PLUGIN_WHITELIST_LINUX,
    )
    return jsonify({
        "analyzers": sorted(_KNOWN_ANALYZERS),
        "volatility": {
            "presets": {
                "fast": {
                    "windows": list(PRESET_FAST_WINDOWS),
                    "linux":   list(PRESET_FAST_LINUX),
                },
                "full": {
                    "windows": list(PRESET_FULL_WINDOWS),
                    "linux":   list(PRESET_FULL_LINUX),
                },
                "custom": "see plugin_whitelist",
            },
            "plugin_whitelist": {
                "windows": sorted(PLUGIN_WHITELIST_WINDOWS),
                "linux":   sorted(PLUGIN_WHITELIST_LINUX),
            },
        },
    }), 200


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
# DELETE /api/v1/cache/<acquisition_id> — evict cached dump
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

# ===========================================================================
# MISP ENRICHMENT ENDPOINTS — Stage F.2 Step G
# ---------------------------------------------------------------------------
# Dedicated routes for the MISP enricher. We deliberately do NOT add
# 'misp' to _KNOWN_ANALYZERS / reuse POST /analyses/<acquisition_id>:
# the enricher is structurally a different operation (input is another
# analysis JSON, not a RAM dump; no preset/plugins; no acquisition
# existence check needed). Keeping it on its own endpoint avoids
# branchy validation logic in the volatility path and makes the API
# surface easier to read for thesis-defence and future maintainers.
#
# Results — being plain analysis-misp-*.json objects in the Swift
# 'forensics' container — are already addressable via the existing
# generic endpoints:
#   - GET /api/v1/analyses/<acquisition_id>     -> lists ALL analyses
#     for that dump, including the MISP enrichments, sorted newest-
#     first (filename embeds UTC).
#   - GET /api/v1/analyses/by-id/<analysis_id>  -> returns the raw
#     JSON of an analysis-misp-*.json by its Swift object name.
#     The dashboard's "Download JSON" link will point here.
# No new read endpoints are needed; the dispatcher already names the
# Swift object as 'analysis-misp-<acquisition_id>-<UTC>-<job8>.json',
# so the substring-match filter in list-analyses picks it up for free.
# ===========================================================================

import re as _re

# Parse the acquisition_id out of a Volatility analysis filename
# WITHOUT making an extra Swift HEAD round-trip. Pattern:
#   analysis-volatility[-<preset>]-<UUID>-<UTC>-<job8>.json
# UUID is RFC4122 8-4-4-4-12; preset is one of fast/full/custom.
# Anything else is rejected at the API boundary (400 malformed_input).
_ACQ_FROM_VOL_ANALYSIS = _re.compile(
    r'^analysis-volatility'
    r'(?:-(?:fast|full|custom))?'
    r'-(?P<acq>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
    r'-\d{8}T\d{6}Z-[0-9a-f]{8}\.json$'
)


@api_v1_bp.route("/misp-enrichments", methods=["POST"])
def trigger_misp_enrichment_endpoint():
    """Start a new async MISP enrichment job.

    Body JSON:
        {"input_analysis_id": "analysis-volatility-..."}

    The input MUST be a Volatility analysis (the enricher refuses
    other source types — see MispEnricher.run() preconditions). The
    acquisition_id is extracted from the filename pattern so we can
    populate the job record consistently with the volatility-side
    pipeline (same field set in JobManager).

    Returns 202 with the job_id and the polling URL, identical
    contract shape to POST /api/v1/analyses/<acquisition_id>.
    """
    cfg = _get_cfg()
    jobs = _get_jobs()

    try:
        body = request.get_json(silent=True) or {}
    except Exception:  # noqa: BLE001
        body = {}

    input_analysis_id = (body.get("input_analysis_id") or "").strip()
    if not input_analysis_id:
        return jsonify({
            "error":   "missing_field",
            "message": "body field 'input_analysis_id' is required",
        }), 400

    # Pattern validation + acquisition_id extraction in one shot.
    m = _ACQ_FROM_VOL_ANALYSIS.match(input_analysis_id)
    if not m:
        return jsonify({
            "error":   "malformed_analysis_id",
            "message": (
                f"input_analysis_id {input_analysis_id!r} does not match "
                f"the expected pattern "
                f"'analysis-volatility[-<preset>]-<uuid>-<UTC>-<job8>.json'. "
                f"MISP enrichment only accepts a Volatility analysis as input."
            ),
        }), 400
    acquisition_id = m.group("acq")

    # Verify the Swift object exists before spawning a worker. HEAD
    # is cheap (~1 round-trip), and the alternative (let the worker
    # discover the missing object and fail_job) would leave a
    # zombie 'failed' record in the dashboard for a simple typo.
    try:
        from forensicnova_analyzer.swift import (
            _authenticate, _resolve_password,
        )
        import swiftclient
        password = _resolve_password(None)
        url, token = _authenticate(cfg, password)
        swiftclient.client.head_object(
            url=url,
            token=token,
            container=cfg.swift_container,
            name=input_analysis_id,
        )
    except swiftclient.ClientException as exc:
        if getattr(exc, "http_status", None) == 404:
            return jsonify({
                "error":   "input_analysis_not_found",
                "message": (
                    f"no Swift object {input_analysis_id!r} in "
                    f"container {cfg.swift_container!r}"
                ),
            }), 404
        log.exception("HEAD check on input_analysis_id failed")
        return jsonify({"error": "internal_error", "message": str(exc)}), 500
    except Exception as exc:  # noqa: BLE001
        log.exception("HEAD check unexpectedly failed")
        return jsonify({"error": "internal_error", "message": str(exc)}), 500

    # Operator identity from Keystone token (same audit trail as the
    # volatility endpoint).
    operator = request.environ.get("HTTP_X_USER_NAME") or "anonymous"

    job_id = str(uuid.uuid4())
    jobs.create_job(
        job_id=job_id,
        operator=operator,
        acquisition_id=acquisition_id,
        analyzer="misp",
        preset=None,
        plugins=None,
    )

    # Lazy import to keep this endpoint cheap when the analyzer is
    # not deployed (e.g. minimal API-only test environments).
    from forensicnova_analyzer.jobs_runner import start_misp_enrichment_job
    start_misp_enrichment_job(
        cfg=cfg,
        jobs=jobs,
        job_id=job_id,
        input_analysis_id=input_analysis_id,
        operator=operator,
    )

    log.info(
        "POST /api/v1/misp-enrichments -> 202 "
        "(job_id=%s, input=%s, acq=%s)",
        job_id, input_analysis_id, acquisition_id,
    )
    return jsonify({
        "job_id":            job_id,
        "acquisition_id":    acquisition_id,
        "input_analysis_id": input_analysis_id,
        "analyzer":          "misp",
        "operator":          operator,
        "status":            "pending",
        "poll_url":          f"/api/v1/jobs/{job_id}",
    }), 202
