"""ForensicNova API blueprints.

Two blueprint families live here (only the first is active in FASE 3):

* core_bp — infrastructure endpoints served at root (/health, /version).
            Unauthenticated by design: liveness probes must never require
            Keystone tokens (standard practice, same as OpenStack services
            that expose /healthcheck).

* api_v1_bp — the DFIR REST API, mounted at /api/v1/*.
              Will be introduced in FASE 4 and wrapped by keystonemiddleware
              with role enforcement (forensic_analyst).
              Planned endpoints:
                POST /api/v1/servers/<instance_id>/memory_acquire
                GET  /api/v1/acquisitions/
                GET  /api/v1/acquisitions/<acq_id>
                GET  /api/v1/acquisitions/<acq_id>/report.pdf
                GET  /api/v1/acquisitions/<acq_id>/report.json

For the thesis, additional families will be added following the same
pattern (e.g. /api/v1/acquisitions/<acq_id>/ioc for Volatility results,
/api/v1/acquisitions/<acq_id>/yara for YARA matches).
"""
from __future__ import annotations

import logging

from flask import Blueprint, current_app, jsonify

log = logging.getLogger("forensicnova.api.core")

core_bp = Blueprint("core", __name__)


@core_bp.route("/health", methods=["GET"])
def health():
    """Liveness probe.

    Returns a small, constant JSON payload identifying the service and
    its version. Intentionally unauthenticated — used by systemd, local
    monitoring, and by the examiner during the oral demo.

    The 'version' field comes from app.__version__ via app.config and
    will be embedded in every forensic report for reproducibility.
    """
    version = current_app.config.get("VERSION", "unknown")
    log.debug("health check served (version=%s)", version)
    return jsonify(
        status="ok",
        service="forensicnova",
        version=version,
    )
