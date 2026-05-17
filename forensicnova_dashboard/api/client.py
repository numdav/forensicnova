"""HTTP client for the ForensicNova REST API.

Single source of truth for how the Horizon plugin talks to the
ForensicNova service. Discovers the endpoint URL via Keystone service
catalog (type 'dfir', registered by the ForensicNova DevStack plugin),
falls back to FORENSICNOVA_URL env var. Forwards the request user's
token in X-Auth-Token so the backend authenticates the analyst, not
a service account.

All public functions take a Django ``request`` first because that's
where horizon.api conventions put it and because both the token and
the service catalog live there.

Errors:
    ForensicNovaApiError       — generic backend error, exposes status + msg
    ForensicNovaUnavailable    — connection/timeout, service is down
    ForensicNovaForbidden      — 403, the analyst lacks the required role
    ForensicNovaNotFound       — 404, the resource does not exist
"""
from __future__ import annotations

import logging
import os
from typing import Any, Optional

import requests

LOG = logging.getLogger(__name__)

# Tunables
_CONNECT_TIMEOUT       = 5.0
_READ_TIMEOUT_FAST     = 15.0    # GET /jobs, GET /acquisitions, POST /memory_acquire (returns 202 fast)
_READ_TIMEOUT_DOWNLOAD = 600.0   # streaming PDF / dump downloads

# Keystone service catalog entry registered by the ForensicNova plugin
_CATALOG_SERVICE_TYPE = "dfir"

# Env var fallback when catalog lookup fails
_FALLBACK_URL_ENV = "FORENSICNOVA_URL"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class ForensicNovaApiError(Exception):
    """Base error for any ForensicNova REST call."""
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class ForensicNovaUnavailable(ForensicNovaApiError):
    """The ForensicNova service is unreachable (connection/timeout)."""


class ForensicNovaForbidden(ForensicNovaApiError):
    """The user lacks the required role / policy permission."""


class ForensicNovaNotFound(ForensicNovaApiError):
    """The requested resource does not exist."""


# ---------------------------------------------------------------------------
# Endpoint discovery
# ---------------------------------------------------------------------------

def _endpoint_url(request) -> str:
    """Resolve the ForensicNova REST root URL from the Keystone catalog.

    Falls back to FORENSICNOVA_URL env var. Failing both, raises
    ForensicNovaUnavailable so the dashboard can render a clear error
    instead of returning 500.
    """
    # 1. Service catalog (preferred path, populated by the ForensicNova
    #    plugin via 'openstack service create dfir' + endpoint).
    try:
        catalog = request.user.service_catalog or []
    except AttributeError:
        catalog = []

    for svc in catalog:
        if svc.get("type") != _CATALOG_SERVICE_TYPE:
            continue
        for ep in svc.get("endpoints", []):
            interface = ep.get("interface") or ep.get("publicURL") and "public"
            if interface == "public" and ep.get("url"):
                return ep["url"].rstrip("/")
            if "publicURL" in ep:
                return ep["publicURL"].rstrip("/")

    # 2. Env-var fallback for cross-host deployments.
    fallback = os.environ.get(_FALLBACK_URL_ENV)
    if fallback:
        LOG.info(
            "ForensicNova URL: catalog miss, using %s=%s",
            _FALLBACK_URL_ENV, fallback,
        )
        return fallback.rstrip("/")

    raise ForensicNovaUnavailable(
        "ForensicNova service URL not in Keystone catalog (type 'dfir') "
        f"and {_FALLBACK_URL_ENV} env var is unset. "
        "Ensure the ForensicNova plugin registered the service "
        "(check 'openstack service list' for type=dfir)."
    )


def _token(request) -> str:
    """Return the request's Keystone token id, or raise."""
    try:
        return request.user.token.id
    except AttributeError as exc:
        raise ForensicNovaApiError(
            "no Keystone token on the current request — "
            "user not authenticated to Horizon"
        ) from exc


def _headers(request) -> dict:
    return {
        "X-Auth-Token": _token(request),
        "Accept":       "application/json",
    }


# ---------------------------------------------------------------------------
# Internal HTTP helpers
# ---------------------------------------------------------------------------

def _get(request, path: str, *, read_timeout: float = _READ_TIMEOUT_FAST) -> dict:
    url = f"{_endpoint_url(request)}{path}"
    try:
        resp = requests.get(
            url,
            headers=_headers(request),
            timeout=(_CONNECT_TIMEOUT, read_timeout),
        )
    except (requests.ConnectionError, requests.Timeout) as exc:
        raise ForensicNovaUnavailable(
            f"ForensicNova unreachable at {url}: {exc}"
        ) from exc
    return _parse_or_raise(resp, url)


def _post(request, path: str, body: Optional[dict] = None) -> dict:
    url = f"{_endpoint_url(request)}{path}"
    try:
        resp = requests.post(
            url,
            json=body,
            headers=_headers(request),
            timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT_FAST),
        )
    except (requests.ConnectionError, requests.Timeout) as exc:
        raise ForensicNovaUnavailable(
            f"ForensicNova unreachable at {url}: {exc}"
        ) from exc
    return _parse_or_raise(resp, url)


def _stream(request, path: str) -> requests.Response:
    """Return a streaming Response for download endpoints. Caller closes."""
    url = f"{_endpoint_url(request)}{path}"
    try:
        resp = requests.get(
            url,
            headers=_headers(request),
            timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT_DOWNLOAD),
            stream=True,
        )
    except (requests.ConnectionError, requests.Timeout) as exc:
        raise ForensicNovaUnavailable(
            f"ForensicNova unreachable at {url}: {exc}"
        ) from exc
    if resp.status_code == 403:
        resp.close()
        raise ForensicNovaForbidden(f"403 on {url}", status=403)
    if resp.status_code == 404:
        resp.close()
        raise ForensicNovaNotFound(f"404 on {url}", status=404)
    if not resp.ok:
        body = (resp.text or "")[:500]
        resp.close()
        raise ForensicNovaApiError(
            f"backend {resp.status_code} on {url}: {body}",
            status=resp.status_code,
        )
    return resp


def _parse_or_raise(resp: requests.Response, url: str) -> dict:
    if resp.status_code == 403:
        raise ForensicNovaForbidden(
            f"403 Forbidden on {url}: {(resp.text or '')[:300]}",
            status=403,
        )
    if resp.status_code == 404:
        raise ForensicNovaNotFound(
            f"404 Not Found on {url}", status=404,
        )
    if not resp.ok:
        raise ForensicNovaApiError(
            f"backend {resp.status_code} on {url}: "
            f"{(resp.text or '')[:300]}",
            status=resp.status_code,
        )
    try:
        return resp.json()
    except ValueError as exc:
        raise ForensicNovaApiError(
            f"non-JSON response from {url}: {(resp.text or '')[:200]}"
        ) from exc


# ---------------------------------------------------------------------------
# Public API — match horizon.api conventions: function per resource action
# ---------------------------------------------------------------------------

def list_acquisitions(request) -> list[dict]:
    """GET /api/v1/acquisitions/  — returns list of acquisition summaries."""
    body = _get(request, "/api/v1/acquisitions/")
    return body.get("acquisitions", []) or []


def get_acquisition(request, acquisition_id: str) -> dict:
    """GET /api/v1/acquisitions/<id>  — returns the full report dict."""
    return _get(request, f"/api/v1/acquisitions/{acquisition_id}")


def list_servers(request) -> list[dict]:
    """GET /api/v1/servers/  — cross-tenant Nova server list."""
    body = _get(request, "/api/v1/servers/")
    return body.get("servers", []) or []


def trigger_acquisition(request, instance_id: str) -> dict:
    """POST /api/v1/servers/<id>/memory_acquire  — async, returns {job_id, ...}.

    Returns 202 in milliseconds; the actual pipeline runs in a background
    thread on the ForensicNova service. The caller should redirect to
    the watch view, which polls get_job() every 2 seconds.
    """
    return _post(request, f"/api/v1/servers/{instance_id}/memory_acquire")


def get_job(request, job_id: str) -> dict:
    """GET /api/v1/jobs/<id>  — job status with phase, label, elapsed_seconds."""
    return _get(request, f"/api/v1/jobs/{job_id}")


def list_jobs(request) -> list[dict]:
    """GET /api/v1/jobs/  — all jobs, most recent first."""
    body = _get(request, "/api/v1/jobs/")
    return body.get("jobs", []) or []


def stream_pdf(request, acquisition_id: str) -> requests.Response:
    """Streaming GET for the PDF report. Caller is responsible for close()."""
    return _stream(request, f"/api/v1/acquisitions/{acquisition_id}/report.pdf")


def stream_json_report(request, acquisition_id: str) -> requests.Response:
    """Streaming GET for the JSON report download.

    Backend F3.5 exposes this endpoint without a file extension
    (route ``download_acquisition_report`` in app/api/v1.py).
    """
    return _stream(request, f"/api/v1/acquisitions/{acquisition_id}/report")


def stream_dump(request, acquisition_id: str) -> requests.Response:
    """Streaming GET for the raw dump (large — uses long timeout)."""
    return _stream(request, f"/api/v1/acquisitions/{acquisition_id}/dump")
