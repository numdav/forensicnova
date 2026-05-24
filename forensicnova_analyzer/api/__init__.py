"""
Blueprint registry for forensicnova_analyzer.

Two blueprints:

  - core_bp: unauthenticated endpoints for health and version checks
    (no url_prefix). They mirror the pattern of the acquisition backend
    so external monitoring (e.g. a systemd-check script) can probe both
    services the same way.

  - api_v1_bp: stub blueprint, currently empty. Will be populated in
    later phases with:
      POST /analyses/<acquisition_id>     (trigger async analysis)
      GET  /analyses/<acquisition_id>     (list analyses for a dump)
      GET  /analyses/<analysis_id>        (full result)
      GET  /jobs/<job_id>                 (job status polling)
      GET  /jobs/                         (analyzer jobs list)

    When authenticated endpoints are added, keystonemiddleware will be
    activated (env "HTTP_X_AUTH_TOKEN") in the create_app() factory.
"""

from flask import Blueprint, jsonify

# Blueprint for unauthenticated endpoints.
# Exposed at the root of the backend: /health, /version
core_bp = Blueprint("core", __name__)


# API v1 blueprint — stub.
# Registered with url_prefix="/api/v1" in the create_app() factory.
# Will be populated in subsequent commits.
api_v1_bp = Blueprint("api_v1", __name__)


@core_bp.route("/health", methods=["GET"])
def health():
    """Health probe.

    Used by:
      - systemd post-start (curl probe, see plugin.sh)
      - external monitoring
      - quick debugging

    Response: 200 OK + JSON with service identification. The `service`
    field lets clients distinguish this from the acquisition backend
    (both respond on /health but with different payloads).
    """
    from forensicnova_analyzer import __version__
    return jsonify({
        "service": "forensicnova-analyzer",
        "status": "ok",
        "version": __version__,
    }), 200


@core_bp.route("/version", methods=["GET"])
def version():
    """Version info — useful for debugging and for dashboards that want
    to surface the analyzer backend version to users.
    """
    from forensicnova_analyzer import __version__
    return jsonify({
        "service": "forensicnova-analyzer",
        "version": __version__,
    }), 200

# Trigger route registration: importing v1 here causes Flask to
# execute the @api_v1_bp.route(...) decorators in v1.py at package
# import time. Without this line v1.py would never be imported and
# the routes would silently not exist.
from . import v1  # noqa: F401
