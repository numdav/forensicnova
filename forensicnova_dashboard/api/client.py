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

# Keystone service catalog entry for the analyzer backend (E3+).
# Registered separately by the plugin so the dashboard can discover
# the analyzer URL independently of the acquisition backend.
_CATALOG_SERVICE_TYPE_ANALYZER = "dfir-analyzer"

# Env var fallback when catalog lookup fails
_FALLBACK_URL_ENV = "FORENSICNOVA_URL"

# Env var fallback specifically for the analyzer backend
_FALLBACK_URL_ENV_ANALYZER = "FORENSICNOVA_ANALYZER_URL"


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

def _endpoint_url(
    request,
    service_type: str = _CATALOG_SERVICE_TYPE,
    fallback_env: str = _FALLBACK_URL_ENV,
) -> str:
    """Resolve a ForensicNova REST root URL from the Keystone catalog.

    Defaults to the acquisition backend (service type 'dfir', port
    5234). Pass service_type='dfir-analyzer' for the analyzer backend
    (port 5235); both services are registered as separate Keystone
    services by the DevStack plugin.

    Falls back to the corresponding env var when the catalog lookup
    misses. Failing both, raises ForensicNovaUnavailable so the
    dashboard can render a clear error instead of returning 500.
    """
    # 1. Service catalog (preferred path, populated by the ForensicNova
    #    plugin via 'openstack service create <type>' + endpoint).
    try:
        catalog = request.user.service_catalog or []
    except AttributeError:
        catalog = []

    for svc in catalog:
        if svc.get("type") != service_type:
            continue
        for ep in svc.get("endpoints", []):
            interface = ep.get("interface") or ep.get("publicURL") and "public"
            if interface == "public" and ep.get("url"):
                return ep["url"].rstrip("/")
            if "publicURL" in ep:
                return ep["publicURL"].rstrip("/")

    # 2. Env-var fallback for cross-host deployments.
    fallback = os.environ.get(fallback_env)
    if fallback:
        LOG.info(
            "ForensicNova URL: catalog miss for type=%s, using %s=%s",
            service_type, fallback_env, fallback,
        )
        return fallback.rstrip("/")

    raise ForensicNovaUnavailable(
        f"ForensicNova service URL not in Keystone catalog "
        f"(type {service_type!r}) and {fallback_env} env var is unset. "
        f"Ensure the ForensicNova plugin registered the service "
        f"(check 'openstack service list' for type={service_type})."
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

def _get(
    request,
    path: str,
    *,
    read_timeout: float = _READ_TIMEOUT_FAST,
    service_type: str = _CATALOG_SERVICE_TYPE,
    fallback_env: str = _FALLBACK_URL_ENV,
) -> dict:
    url = f"{_endpoint_url(request, service_type, fallback_env)}{path}"
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


def _post(
    request,
    path: str,
    body: Optional[dict] = None,
    *,
    service_type: str = _CATALOG_SERVICE_TYPE,
    fallback_env: str = _FALLBACK_URL_ENV,
) -> dict:
    url = f"{_endpoint_url(request, service_type, fallback_env)}{path}"
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


def _delete(
    request,
    path: str,
    *,
    service_type: str = _CATALOG_SERVICE_TYPE,
    fallback_env: str = _FALLBACK_URL_ENV,
) -> dict:
    """HTTP DELETE helper, symmetric to _get and _post.

    Used by Horizon Delete actions (e.g. delete_analyzer_job). The
    backend's DELETE endpoints are idempotent: they return 200 with a
    structured body even when the target was already absent, so this
    helper does not special-case 404 the way _stream does.
    """
    url = f"{_endpoint_url(request, service_type, fallback_env)}{path}"
    try:
        resp = requests.delete(
            url,
            headers=_headers(request),
            timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT_FAST),
        )
    except (requests.ConnectionError, requests.Timeout) as exc:
        raise ForensicNovaUnavailable(
            f"ForensicNova unreachable at {url}: {exc}"
        ) from exc
    return _parse_or_raise(resp, url)


def _stream(
    request,
    path: str,
    *,
    service_type: str = _CATALOG_SERVICE_TYPE,
    fallback_env: str = _FALLBACK_URL_ENV,
) -> requests.Response:
    """Return a streaming Response for download endpoints. Caller closes."""
    url = f"{_endpoint_url(request, service_type, fallback_env)}{path}"
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

    Backend exposes this endpoint without a file extension
    (route ``download_acquisition_report`` in app/api/v1.py).
    """
    return _stream(request, f"/api/v1/acquisitions/{acquisition_id}/report")


def stream_dump(request, acquisition_id: str) -> requests.Response:
    """Streaming GET for the raw dump (large — uses long timeout)."""
    return _stream(request, f"/api/v1/acquisitions/{acquisition_id}/dump")


# ===========================================================================
# Analyzer backend (service type 'dfir-analyzer', port 5235)
# ===========================================================================
#
# These functions target the analyzer service, separately registered in
# Keystone by the DevStack plugin. They share the same _get/_post helpers
# but route via service_type='dfir-analyzer' so endpoint discovery hits
# the right base URL.

def _get_analyzer(
    request, path: str, *, read_timeout: float = _READ_TIMEOUT_FAST,
) -> dict:
    return _get(
        request, path,
        read_timeout=read_timeout,
        service_type=_CATALOG_SERVICE_TYPE_ANALYZER,
        fallback_env=_FALLBACK_URL_ENV_ANALYZER,
    )


def _post_analyzer(request, path: str, body: Optional[dict] = None) -> dict:
    return _post(
        request, path, body,
        service_type=_CATALOG_SERVICE_TYPE_ANALYZER,
        fallback_env=_FALLBACK_URL_ENV_ANALYZER,
    )


def _delete_analyzer(request, path: str) -> dict:
    return _delete(
        request, path,
        service_type=_CATALOG_SERVICE_TYPE_ANALYZER,
        fallback_env=_FALLBACK_URL_ENV_ANALYZER,
    )


def list_analyses_for_acquisition(
    request, acquisition_id: str,
) -> list[dict]:
    """GET /api/v1/analyses/<acquisition_id> — list analyses for one acq.

    Returns the list of analysis summaries (dict with analysis_id,
    size_bytes, last_modified, etag). Sorted newest first by the
    backend.
    """
    body = _get_analyzer(
        request, f"/api/v1/analyses/{acquisition_id}",
    )
    return body.get("analyses", []) or []


def get_analysis(request, analysis_id: str) -> dict:
    """GET /api/v1/analyses/by-id/<analysis_id> — full analysis JSON.

    The analysis_id is the Swift object name (e.g.
    'analysis-volatility-fast-<acq>-<UTC>-<job8>.json'). Path-encoded
    automatically by requests.
    """
    return _get_analyzer(request, f"/api/v1/analyses/by-id/{analysis_id}")


def trigger_analysis(
    request,
    acquisition_id: str,
    *,
    analyzer: str,
    preset: Optional[str] = None,
    plugins: Optional[list[str]] = None,
) -> dict:
    """POST /api/v1/analyses/<acq_id> — async, returns {job_id, ...}.

    Returns 202 in milliseconds; the actual pipeline (download dump,
    hash check, plugin loop, upload JSON) runs in a background thread
    on the analyzer service. The caller should redirect to the watch
    view, which polls get_analyzer_job() every 2-3 seconds.

    :param analyzer: 'noop' | 'volatility'
    :param preset:   'fast' | 'full' | 'custom' (only for volatility)
    :param plugins:  explicit plugin list (only with preset='custom')
    """
    body: dict[str, Any] = {"analyzer": analyzer}
    if preset is not None:
        body["preset"] = preset
    if plugins:
        body["plugins"] = plugins
    return _post_analyzer(
        request, f"/api/v1/analyses/{acquisition_id}", body,
    )


def trigger_misp_enrichment(request, input_analysis_id: str) -> dict:
    """POST /api/v1/misp-enrichments — async, returns {job_id, ...}.

    Enriches an existing volatility analysis with MISP threat intel.
    The body carries the source analysis object name (NOT a dump):
    the backend extracts IOCs from that analysis-volatility-*.json,
    queries MISP, and writes an analysis-misp-*.json. Returns 202 in
    milliseconds; the enrichment runs in a background thread. Caller
    redirects to the watch view, which polls get_analyzer_job().

    This targets the dedicated MISP endpoint (NOT trigger_analysis with
    analyzer='misp'): the input is another analysis, not a dump, so it
    has no preset/plugins and a distinct request shape.
    """
    return _post_analyzer(
        request, "/api/v1/misp-enrichments",
        {"input_analysis_id": input_analysis_id},
    )


def get_analyzer_job(request, job_id: str) -> dict:
    """GET /api/v1/jobs/<id> on the analyzer backend.

    Distinct from the acquisition-side get_job(): the analyzer has its
    own JobManager with separate jobs/ directory. Job IDs are unique
    per backend (a job_id from the analyzer will NOT resolve on the
    acquisition backend, and vice versa).
    """
    return _get_analyzer(request, f"/api/v1/jobs/{job_id}")


def list_analyzer_jobs(request) -> list[dict]:
    """GET /api/v1/jobs on the analyzer backend — all analyses jobs."""
    body = _get_analyzer(request, "/api/v1/jobs")
    return body.get("jobs", []) or []


def list_plugins(request) -> dict:
    """GET /api/v1/plugins — analyzers + presets + plugin whitelist.

    Used by the New analysis form to populate analyzer dropdown,
    preset dropdown, and the custom plugin multi-select grouped by
    SANS macro-area.
    """
    return _get_analyzer(request, "/api/v1/plugins")


def stream_analysis_json(request, analysis_id: str) -> requests.Response:
    """Streaming GET for the analysis JSON (caller closes).

    Used by the 'Download JSON' button on the detail view to push the
    raw analysis file to the browser without buffering it server-side.
    """
    return _stream(
        request, f"/api/v1/analyses/by-id/{analysis_id}",
        service_type=_CATALOG_SERVICE_TYPE_ANALYZER,
        fallback_env=_FALLBACK_URL_ENV_ANALYZER,
    )


def delete_analyzer_job(request, job_id: str) -> dict:
    """DELETE /api/v1/jobs/<job_id> on the analyzer backend.

    Removes the job record from the analyzer's local jobs/ directory
    AND cascades the deletion of any Swift analysis-*.json object that
    job produced. Idempotent at both legs: missing job file or already-
    deleted Swift object both yield a successful 200 with the relevant
    deleted=false flag in the response body.

    Used by the Analyses table's Delete row action. Useful especially
    after an unstack/stack cycle to clear orphan jobs whose Swift
    objects no longer exist (the container is rebuilt empty), and for
    routine cleanup of test/failed runs during development.

    Returns the structured response body, useful for the dashboard's
    flash messages:
        {
          "job_id":          "<uuid>",
          "removed_job":     bool,
          "previous_status": "completed" | "failed" | ...,
          "analyzer":        "volatility",
          "acquisition_id":  "<uuid>",
          "analysis_id":     "analysis-...json" or None,
          "cascade_swift":   {"object_name": ..., "deleted": bool, "status": ...},
        }
    """
    return _delete_analyzer(request, f"/api/v1/jobs/{job_id}")
