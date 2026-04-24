"""ForensicNova dashboard — loopback client to the forensic REST API.

The dashboard consumes the same HTTP API that external clients (curl,
scripts, Volatility automation in thesis) use.  Rationale covered in
app/dashboard/__init__.py: zero parallel code paths, single auth model.

Error taxonomy raised to views (all inherit from ApiClientError):
  - SessionRevokedError : API returned 401    (token revoked/expired)
  - ApiForbiddenError   : API returned 403    (role removed mid-session)
  - ApiNotFoundError    : API returned 404    (resource does not exist)
  - AcquisitionError    : acquisition pipeline failed (500/502 on POST)
  - ApiUnavailableError : transport or other 5xx
  - ApiClientError      : other 4xx           (likely dashboard bug)

Views do NOT catch these — the blueprint-level errorhandlers in routes.py
map them to redirects + flash messages uniformly.
"""
from __future__ import annotations

import logging

import requests
from flask import session

log = logging.getLogger("forensicnova.dashboard.api")

# Loopback target — same WSGI process, different blueprint.
_API_BASE = "http://127.0.0.1:5234/api/v1"

# Timeouts.
# - GETs: generous read (15s) for list ops that iterate Swift objects
# - POST memory_acquire: very long read (10 min) because the acquisition
#   pipeline runs synchronously end-to-end (libvirt dump + MD5/SHA1 +
#   Swift upload + secure delete + report).  A 512 MB cirros takes ~12s;
#   a 4 GB Windows Server can take 2-3 minutes; we leave headroom.
#   If the browser-side ever times out before this, the server-side
#   pipeline will still complete and the new acquisition will show up
#   in the list on refresh — no data loss.
_CONNECT_TIMEOUT          = 2.0
_READ_TIMEOUT_FAST        = 15.0
_READ_TIMEOUT_ACQUISITION = 600.0


class ApiClientError(RuntimeError):
    """Generic error from a loopback API call."""


class SessionRevokedError(ApiClientError):
    """API returned 401 — token revoked or expired."""


class ApiForbiddenError(ApiClientError):
    """API returned 403 — forensic_analyst role missing."""


class ApiNotFoundError(ApiClientError):
    """API returned 404 — the requested resource does not exist."""


class AcquisitionError(ApiClientError):
    """The acquisition pipeline itself failed (libvirt/integrity/fs/other).

    Distinct from ApiUnavailableError because the API replied — it just
    replied with an error from the pipeline.  The error payload from the
    API is preserved in .detail for diagnostic display.
    """

    def __init__(self, message: str, detail: dict):
        super().__init__(message)
        self.detail = detail


class ApiUnavailableError(ApiClientError):
    """API did not respond (transport error or unexpected 5xx on GET)."""


# ---------------------------------------------------------------------------
# Public API — one function per endpoint we consume
# ---------------------------------------------------------------------------

def list_acquisitions() -> dict:
    """Fetch the summary listing of all acquisitions."""
    return _get("/acquisitions/")


def get_acquisition(acquisition_id: str) -> dict:
    """Fetch a single acquisition's full report (schema v1.1)."""
    return _get(f"/acquisitions/{acquisition_id}")


def list_servers() -> dict:
    """Fetch the cross-tenant list of Nova instances (FASE 5 step 2e)."""
    return _get("/servers/")


def trigger_acquisition(instance_id: str) -> dict:
    """Synchronously trigger a memory acquisition and return the result.

    Blocks until the full pipeline (libvirt dump, hashing, Swift upload,
    secure delete, report generation) completes on the server side.

    :raises AcquisitionError: if the pipeline itself failed.
    :raises SessionRevokedError: on 401.
    :raises ApiForbiddenError:   on 403.
    :raises ApiUnavailableError: on transport or generic 5xx.
    """
    return _post(
        f"/servers/{instance_id}/memory_acquire",
        read_timeout=_READ_TIMEOUT_ACQUISITION,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _token() -> str:
    """Pull the session's Keystone token or raise SessionRevokedError."""
    tok = session.get("keystone_token")
    if not tok:
        raise SessionRevokedError("no keystone_token in session")
    return tok


def _raise_for_common_errors(resp, path: str) -> None:
    """Map 401/403/404 to typed exceptions; caller handles 2xx vs 5xx."""
    if resp.status_code == 401:
        log.info("API 401 on %s — token revoked mid-session", path)
        raise SessionRevokedError("the API rejected your session token")
    if resp.status_code == 403:
        log.info("API 403 on %s — forensic_analyst role missing", path)
        raise ApiForbiddenError(
            "the API denied access — required role no longer present"
        )
    if resp.status_code == 404:
        log.info("API 404 on %s", path)
        raise ApiNotFoundError(f"resource not found: {path}")


def _get(path: str) -> dict:
    """HTTP GET on the loopback API with session token; return parsed JSON."""
    url = _API_BASE.rstrip("/") + path
    headers = {"X-Auth-Token": _token()}

    log.debug("GET %s", url)
    try:
        resp = requests.get(
            url,
            headers=headers,
            timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT_FAST),
        )
    except requests.exceptions.RequestException as exc:
        log.warning("loopback API unreachable: %s", exc)
        raise ApiUnavailableError(
            f"cannot reach forensic API: {exc}"
        ) from exc

    _raise_for_common_errors(resp, path)

    if resp.status_code >= 500:
        log.error(
            "API returned %d on %s: %s",
            resp.status_code, path, resp.text[:200],
        )
        raise ApiUnavailableError(f"API returned HTTP {resp.status_code}")

    if resp.status_code >= 400:
        log.error(
            "API returned %d on %s: %s",
            resp.status_code, path, resp.text[:200],
        )
        raise ApiClientError(
            f"API error HTTP {resp.status_code}: {resp.text[:120]}"
        )

    try:
        return resp.json()
    except ValueError as exc:
        raise ApiClientError(
            f"API returned non-JSON body: {resp.text[:100]}"
        ) from exc


def _post(path: str, read_timeout: float) -> dict:
    """HTTP POST on the loopback API with extended timeout; return JSON.

    On 500/502 (pipeline error) raises AcquisitionError with the API's
    structured error detail so the UI can show a meaningful message.
    """
    url = _API_BASE.rstrip("/") + path
    headers = {"X-Auth-Token": _token()}

    log.info("POST %s (read_timeout=%ds)", url, int(read_timeout))
    try:
        resp = requests.post(
            url,
            headers=headers,
            timeout=(_CONNECT_TIMEOUT, read_timeout),
        )
    except requests.exceptions.RequestException as exc:
        log.warning("loopback API unreachable on POST: %s", exc)
        raise ApiUnavailableError(
            f"cannot reach forensic API: {exc}"
        ) from exc

    _raise_for_common_errors(resp, path)

    if resp.status_code in (500, 502):
        # Pipeline-level failure — try to extract the API's JSON error body.
        try:
            detail = resp.json()
        except ValueError:
            detail = {"error": "unknown", "detail": resp.text[:200]}
        log.error(
            "acquisition pipeline failed HTTP %d: %s",
            resp.status_code, detail,
        )
        raise AcquisitionError(
            detail.get("detail") or detail.get("error") or
            "acquisition pipeline failed",
            detail=detail,
        )

    if resp.status_code >= 500:
        log.error("API %d on POST %s: %s", resp.status_code, path, resp.text[:200])
        raise ApiUnavailableError(f"API returned HTTP {resp.status_code}")

    if resp.status_code >= 400:
        log.error("API %d on POST %s: %s", resp.status_code, path, resp.text[:200])
        raise ApiClientError(
            f"API error HTTP {resp.status_code}: {resp.text[:120]}"
        )

    try:
        return resp.json()
    except ValueError as exc:
        raise ApiClientError(
            f"API returned non-JSON body: {resp.text[:100]}"
        ) from exc
