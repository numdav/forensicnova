"""
forensicnova_analyzer/api/v1.py — authenticated REST endpoints.

STUB: this file will be populated in subsequent commits with:

  POST /api/v1/analyses/<acquisition_id>
      Trigger an asynchronous forensic analysis.
      Body JSON: {"analyzer": "noop"|"volatility",
                  "preset": "fast"|"full"|"custom",
                  "plugins": [...] (only for custom)}
      Response: 202 Accepted, {job_id, analysis_id, status, phase}

  GET /api/v1/analyses/<acquisition_id>
      List analyses (possibly multiple) for a given acquisition_id.

  GET /api/v1/analyses/<analysis_id>
      Full result of a specific analysis.

  GET /api/v1/jobs/<job_id>
      Job status polling (status, phase, progress_pct).
      Same Feature 3.5 pattern as the acquisition backend.

  GET /api/v1/jobs/
      List analyzer jobs.

All endpoints will require Keystone authentication via
keystonemiddleware. The middleware will be activated in create_app()
once this module starts being populated.
"""

# The blueprint is imported from api/__init__.py and registered by the
# create_app() factory. Real routes arrive in later commits.
from forensicnova_analyzer.api import api_v1_bp  # noqa: F401
