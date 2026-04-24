"""ForensicNova dashboard — loopback client to the forensic REST API.

The dashboard consumes the same HTTP API that external clients (curl,
scripts, Volatility automation in thesis) use.  Rationale covered in
app/dashboard/__init__.py: zero parallel code paths, single auth model.

Error taxonomy raised to views:
  - SessionRevokedError  : API returned 401 (token revoked mid-session)
  - ApiUnavailableError  : transport failure or 5xx from API
  - ApiClientError       : other 4xx responses (bug in dashboard code)

Views do NOT catch these — the blueprint-level errorhandlers in routes.py
map them to redirects + flash messages uniformly.
"""
from __future__ import annotations

import logging

import requests
from flask import session

log = logging.getLogger("forensicnova.dashboard.api")

# Loopback target — same WSGI process, different blueprint.
# Not configurable by design: if the dashboard ever runs on a separate
# host from the API, make this a Config entry then.
_API_BASE = "http://127.0.0.1:5234/api/v1"

# Timeouts — generous on read (listing iterates over Swift objects),
# short on connect (loopback is always fast or broken).
_CONNECT_TIMEOUT = 2.0
_READ_TIMEOUT    = 15.0


class ApiClientError(RuntimeError):
    """Generic error from a loopback API call."""


class SessionRevokedError(ApiClientError):
    """API returned 401 — the user's token is no longer valid.

    This happens when an admin revokes the token mid-session, or when
    Keystone's clock disagrees with ours about expiration.
    """


class ApiUnavailableError(ApiClientError):
    """API did not respond (transport error or 5xx)."""


# ---------------------------------------------------------------------------
# Public API — one function per endpoint we consume
# ---------------------------------------------------------------------------

def list_acquisitions() -> dict:
    """Fetch the summary listing of all acquisitions.

    :returns: dict with keys 'count' (int), 'acquisitions' (list of summaries).
    """
    return _get("/acquisitions/")


def get_acquisition(acquisition_id: str) -> dict:
    """Fetch a single acquisition's full report (schema v1.1)."""
    return _get(f"/acquisitions/{acquisition_id}")


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _token() -> str:
    """Pull the session's Keystone token or raise SessionRevokedError."""
    tok = session.get("keystone_token")
    if not tok:
        # Defensive: @login_required should have caught this.
        raise SessionRevokedError("no keystone_token in session")
    return tok


def _get(path: str) -> dict:
    """HTTP GET on the loopback API with session token; return parsed JSON.

    :raises SessionRevokedError: on HTTP 401.
    :raises ApiUnavailableError: on transport error or HTTP 5xx.
    :raises ApiClientError:      on other 4xx responses.
    """
    url = _API_BASE.rstrip("/") + path
    headers = {"X-Auth-Token": _token()}

    log.debug("GET %s", url)
    try:
        resp = requests.get(
            url,
            headers=headers,
            timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT),
        )
    except requests.exceptions.RequestException as exc:
        log.warning("loopback API unreachable: %s", exc)
        raise ApiUnavailableError(
            f"cannot reach forensic API: {exc}"
        ) from exc

    if resp.status_code == 401:
        log.info("API 401 on %s — token revoked mid-session", path)
        raise SessionRevokedError("the API rejected your session token")

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
