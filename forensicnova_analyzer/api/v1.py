"""
forensicnova_analyzer/api/v1.py — REST endpoints (v1).

Stage E2.2 introduces two read-only, unauthenticated endpoints. They
let the dashboard (and curl-based debugging) enumerate the acquisitions
currently stored in Swift, without yet involving the JobManager,
Volatility, or Keystone auth — those arrive in E2.4 and E2.5.

Endpoints in this commit:

  GET /api/v1/acquisitions
      Returns a JSON list of flattened acquisition summaries.

      Response 200:
          {
            "count": <int>,
            "acquisitions": [
              {
                "schema_version":   "1.2",
                "acquisition_id":   "<uuid>",
                "instance_name":    "<vm-name>",
                "instance_id":      "<uuid>",
                "dump_object_name": "dump-<vm>-<UTC>.raw",
                "dump_swift_object":"<container>/<dump_object_name>",
                "dump_md5":         "<32 hex>",
                "dump_sha1":        "<40 hex>",
                "dump_size_bytes":  <int>,
                "completed_at":     "<iso8601>"
              },
              ...
            ]
          }

      Reports with an unsupported schema_version or otherwise malformed
      content are skipped (with a WARNING in the analyzer log) rather
      than turning the entire listing into a 500 — chain of custody is
      best preserved by reporting what we can, and surfacing the bad
      ones in logs.

  GET /api/v1/acquisitions/<acquisition_id>
      Returns the full acquisition report plus its summary.

      Response 200:
          {"summary": {...}, "report": {...}}
      Response 404:
          {"error": "acquisition_not_found", "message": "..."}
      Response 422:
          {"error": "unsupported_schema",
           "message": "...", "schema_version": "<seen>"}

Subsequent commits will add (Stage E2.4 / E2.5):

  POST /api/v1/analyses/<acquisition_id>
      Trigger an async analysis. 202 Accepted + {job_id, ...}.

  GET  /api/v1/jobs/<job_id>
      Job status polling.

  GET  /api/v1/analyses/<acquisition_id>
      List analyses already produced for a given acquisition.

  GET  /api/v1/analyses/<analysis_id>
      Full analysis result.

Authentication via keystonemiddleware will be activated in the
create_app() factory once the async endpoints are wired (E2.5).
"""
from __future__ import annotations

import logging

from flask import current_app, jsonify

from forensicnova_analyzer import swift
from forensicnova_analyzer.api import api_v1_bp

log = logging.getLogger("forensicnova_analyzer.api.v1")


def _get_cfg():
    """Fetch the AnalyzerConfig instance from the Flask app context.

    The factory `create_app()` stores it under
    app.config["FORENSICNOVA_ANALYZER"] at startup; every endpoint
    reads it from there rather than via a module-global so unit tests
    can swap configurations cleanly.
    """
    return current_app.config["FORENSICNOVA_ANALYZER"]


# ---------------------------------------------------------------------------
# GET /api/v1/acquisitions — list summaries
# ---------------------------------------------------------------------------

@api_v1_bp.route("/acquisitions", methods=["GET"])
def list_acquisitions_endpoint():
    """List flattened summaries of every acquisition report in Swift."""
    cfg = _get_cfg()
    try:
        reports = swift.list_acquisitions(cfg)
    except Exception as exc:  # noqa: BLE001 — top-level guard for HTTP
        log.exception("list_acquisitions failed")
        return jsonify({
            "error":   "internal_error",
            "message": str(exc),
        }), 500

    summaries: list[dict] = []
    skipped = 0
    for report in reports:
        try:
            summaries.append(swift.summarize_acquisition(report))
        except swift.UnsupportedReportSchema as exc:
            log.warning(
                "skipping acquisition with unsupported schema: %s", exc,
            )
            skipped += 1
        except (KeyError, ValueError, TypeError) as exc:
            # Schema claims a supported version but is structurally
            # malformed. Skip with a louder warning — this is a real bug
            # somewhere upstream and someone should look at the log.
            log.warning(
                "skipping malformed acquisition report (acquisition_id=%r): %s",
                report.get("acquisition_id"), exc,
            )
            skipped += 1

    log.info(
        "GET /api/v1/acquisitions -> %d summaries (%d skipped)",
        len(summaries), skipped,
    )

    return jsonify({
        "count":         len(summaries),
        "acquisitions":  summaries,
        # Surface the skip count so callers (or a future health check)
        # can detect silent data quality issues; zero in a healthy
        # deployment.
        "skipped":       skipped,
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
    except Exception as exc:  # noqa: BLE001 — top-level guard for HTTP
        log.exception("find_acquisition(%s) failed", acquisition_id)
        return jsonify({
            "error":   "internal_error",
            "message": str(exc),
        }), 500

    if report is None:
        log.info(
            "GET /api/v1/acquisitions/%s -> 404 (not found)",
            acquisition_id,
        )
        return jsonify({
            "error":   "acquisition_not_found",
            "message": f"no acquisition with id {acquisition_id!r}",
        }), 404

    try:
        summary = swift.summarize_acquisition(report)
    except swift.UnsupportedReportSchema as exc:
        log.warning(
            "GET /api/v1/acquisitions/%s -> 422 (unsupported schema): %s",
            acquisition_id, exc,
        )
        return jsonify({
            "error":          "unsupported_schema",
            "message":        str(exc),
            "schema_version": report.get("schema_version"),
        }), 422
    except (KeyError, ValueError, TypeError) as exc:
        log.exception(
            "GET /api/v1/acquisitions/%s -> 422 (malformed report)",
            acquisition_id,
        )
        return jsonify({
            "error":   "malformed_report",
            "message": str(exc),
        }), 422

    log.info(
        "GET /api/v1/acquisitions/%s -> 200 (schema_version=%s)",
        acquisition_id, summary.get("schema_version"),
    )

    return jsonify({
        "summary": summary,
        "report":  report,
    }), 200
