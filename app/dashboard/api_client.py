"""ForensicNova dashboard — loopback client to the forensic REST API.

Error taxonomy raised to views (all inherit from ApiClientError):
  - SessionRevokedError : API returned 401    (token revoked/expired)
  - ApiForbiddenError   : API returned 403    (role removed mid-session)
  - ApiNotFoundError    : API returned 404    (resource does not exist)
  - AcquisitionError    : acquisition pipeline failed (500/502 on POST)
  - ApiUnavailableError : transport or other 5xx
  - ApiClientError      : other 4xx
"""
from __future__ import annotations

import logging

import requests
from flask import session

log = logging.getLogger("forensicnova.dashboard.api")

_API_BASE = "http://127.0.0.1:5234/api/v1"

_CONNECT_TIMEOUT          = 2.0
_READ_TIMEOUT_FAST        = 15.0
_READ_TIMEOUT_ACQUISITION = 600.0
_READ_TIMEOUT_DOWNLOAD    = 600.0  # large dumps: 4 GB at 50 MB/s ~ 80s + slack

# Streaming chunk size forwarded from requests to the client.  Matches
# swift_client's _STREAM_CHUNK_SIZE to keep chunking aligned end-to-end.
_DOWNLOAD_CHUNK_SIZE = 1024 * 1024


class ApiClientError(RuntimeError):
    """Generic error from a loopback API call."""


class SessionRevokedError(ApiClientError):
    """API returned 401."""


class ApiForbiddenError(ApiClientError):
    """API returned 403."""


class ApiNotFoundError(ApiClientError):
    """API returned 404."""


class AcquisitionError(ApiClientError):
    """The acquisition pipeline itself failed (libvirt/integrity/fs/other)."""

    def __init__(self, message: str, detail: dict):
        super().__init__(message)
        self.detail = detail


class ApiUnavailableError(ApiClientError):
    """API did not respond (transport or generic 5xx on GET)."""


# ---------------------------------------------------------------------------
# Public API — one function per endpoint we consume
# ---------------------------------------------------------------------------

def list_acquisitions() -> dict:
    return _get("/acquisitions/")


def get_acquisition(acquisition_id: str) -> dict:
    return _get(f"/acquisitions/{acquisition_id}")


def list_servers() -> dict:
    return _get("/servers/")


def trigger_acquisition(instance_id: str) -> dict:
    return _post(
        f"/servers/{instance_id}/memory_acquire",
        read_timeout=_READ_TIMEOUT_ACQUISITION,
    )


def stream_dump(acquisition_id: str):
    """Stream the dump from the API; returns (filename, content_length, chunk_iter).

    Caller wraps the iterator in a Flask Response(stream_with_context) to
    forward to the browser.
    """
    return _stream(f"/acquisitions/{acquisition_id}/dump")


def stream_report(acquisition_id: str):
    """Stream the JSON report from the API as an attachment."""
    return _stream(f"/acquisitions/{acquisition_id}/report")


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _token() -> str:
    tok = session.get("keystone_token")
    if not tok:
        raise SessionRevokedError("no keystone_token in session")
    return tok


def _raise_for_common_errors(resp, path: str) -> None:
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
        log.error("API %d on %s: %s", resp.status_code, path, resp.text[:200])
        raise ApiUnavailableError(f"API returned HTTP {resp.status_code}")

    if resp.status_code >= 400:
        log.error("API %d on %s: %s", resp.status_code, path, resp.text[:200])
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


def _stream(path: str):
    """Open a streaming GET on the API and return (filename, length, iter).

    Uses requests' stream=True so the API response body is read lazily —
    bytes arrive at the dashboard, are forwarded to the browser, and
    leave memory within one chunk's lifetime.  Constant memory.

    :returns: (filename, content_length_str, chunk_iterator)
    :raises SessionRevokedError / ApiForbiddenError / ApiNotFoundError /
            ApiUnavailableError / ApiClientError
    """
    url = _API_BASE.rstrip("/") + path
    headers = {"X-Auth-Token": _token()}

    log.info("STREAM GET %s", url)
    try:
        resp = requests.get(
            url,
            headers=headers,
            stream=True,
            timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT_DOWNLOAD),
        )
    except requests.exceptions.RequestException as exc:
        log.warning("stream API unreachable: %s", exc)
        raise ApiUnavailableError(
            f"cannot reach forensic API: {exc}"
        ) from exc

    _raise_for_common_errors(resp, path)

    if resp.status_code >= 500:
        body = resp.text[:200]
        resp.close()
        log.error("API %d on stream %s: %s", resp.status_code, path, body)
        raise ApiUnavailableError(f"API returned HTTP {resp.status_code}")

    if resp.status_code >= 400:
        body = resp.text[:200]
        resp.close()
        log.error("API %d on stream %s: %s", resp.status_code, path, body)
        raise ApiClientError(
            f"API error HTTP {resp.status_code}: {body[:120]}"
        )

    # Extract filename from Content-Disposition ('attachment; filename="..."').
    cd = resp.headers.get("Content-Disposition", "")
    filename = _extract_filename(cd) or "download.bin"
    content_length = resp.headers.get("Content-Length", "")

    def _iter():
        try:
            for chunk in resp.iter_content(chunk_size=_DOWNLOAD_CHUNK_SIZE):
                if chunk:
                    yield chunk
        finally:
            resp.close()

    return filename, content_length, _iter()


def _extract_filename(content_disposition: str) -> str:
    """Parse filename from a Content-Disposition header (naive, adequate here)."""
    if not content_disposition:
        return ""
    for part in content_disposition.split(";"):
        part = part.strip()
        if part.startswith("filename="):
            value = part[len("filename="):].strip()
            return value.strip('"')
    return ""
