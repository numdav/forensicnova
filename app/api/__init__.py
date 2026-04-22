"""ForensicNova API blueprints.

Two blueprint families live here:

* core_bp — infrastructure endpoints served at root (/health, /version).
            Unauthenticated by design: liveness probes must never require
            Keystone tokens (standard practice, same as OpenStack services
            that expose /healthcheck).

* api_v1_bp — the DFIR REST API, mounted at /api/v1/* by app/__init__.py.
              Protected by keystonemiddleware (auth_token) wired around the
              Flask WSGI app, plus a per-blueprint before_request hook in
              app/api/v1.py that enforces the forensic_analyst role.
              Endpoints (FASE 4):
                POST /api/v1/servers/<instance_id>/memory_acquire
              Endpoints planned for FASE 5+:
                GET  /api/v1/acquisitions/
                GET  /api/v1/acquisitions/<acq_id>
                GET  /api/v1/acquisitions/<acq_id>/report.pdf
                GET  /api/v1/acquisitions/<acq_id>/report.json
"""
from __future__ import annotations

import logging

from flask import Blueprint, current_app, jsonify

log = logging.getLogger("forensicnova.api.core")

core_bp = Blueprint("core", __name__)


@core_bp.route("/health", methods=["GET"])
def health():
    """Liveness probe.  Unauthenticated by design.

    The 'version' field comes from app.__version__ via app.config and
    is embedded in every forensic report for reproducibility.
    """
    version = current_app.config.get("VERSION", "unknown")
    log.debug("health check served (version=%s)", version)
    return jsonify(
        status="ok",
        service="forensicnova",
        version=version,
    )


# Re-export the v1 API blueprint so app/__init__.py can import both from
# a single location:  from app.api import core_bp, api_v1_bp
from app.api.v1 import api_v1_bp  # noqa: E402
