"""ForensicNova dashboard — Keystone v3 authentication helper.

Handles two operations against Keystone identity v3 API:

  1. authenticate(): POST /v3/auth/tokens with username+password scoped
     to a project.  Returns a dict with token + claims + roles.  Validates
     that the required role is present.

  2. revoke_token(): DELETE /v3/auth/tokens on the user's own token
     (used by logout).  Best effort — a revocation failure does not
     prevent session termination client-side.

Error taxonomy (AuthenticationError.reason):
  - "invalid_credentials"      : wrong username or password   (401 from Keystone)
  - "authorization_failure"    : user lacks required role     (our check)
  - "keystone_unavailable"     : network / timeout / 5xx      (transport)
  - "unexpected_response"      : Keystone returned 2xx body we can't parse

This module makes HTTP calls via `requests` (already a venv dep).
We deliberately DO NOT use python-keystoneclient here: its API surface is
huge, its exception hierarchy mixes OSLO noise with auth errors, and it
would pull eventlet into the dashboard request path.  Raw requests keeps
the code 40 lines, debuggable, and stack-trace clean.
"""
from __future__ import annotations

import logging
from typing import Optional

import requests

log = logging.getLogger("forensicnova.dashboard.keystone")

# Keystone v3 auth endpoints are typically mounted under /identity/v3.
# cfg.keystone_auth_url already includes the '/identity' part (see
# the INI written by plugin.sh), so we append '/v3/auth/tokens' only.
_AUTH_TOKENS_PATH = "/v3/auth/tokens"

# Request timeouts — be generous on the read, short on the connect.
# If Keystone is down, we want to fail within ~5 seconds total.
_CONNECT_TIMEOUT = 3.0
_READ_TIMEOUT    = 5.0


class AuthenticationError(Exception):
    """Raised by authenticate() to signal any login-path failure."""

    def __init__(self, message: str, reason: str):
        super().__init__(message)
        self.reason = reason


def authenticate(
    auth_url: str,
    username: str,
    password: str,
    project_name: str,
    required_role: str,
    user_domain_id: str = "default",
    project_domain_id: str = "default",
) -> dict:
    """Obtain a Keystone v3 scoped token and validate role membership.

    :returns: dict with keys:
        - token          (str) the X-Subject-Token header value
        - expires_at     (ISO-8601 UTC string)
        - username       (echoed from Keystone's response)
        - user_id        (uuid)
        - project_name   (echoed — matches the requested scope)
        - project_id     (uuid)
        - roles          (list of role name strings)
    :raises AuthenticationError: on any failure, with .reason set.
    """
    url = auth_url.rstrip("/") + _AUTH_TOKENS_PATH

    payload = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": username,
                        "domain": {"id": user_domain_id},
                        "password": password,
                    }
                },
            },
            "scope": {
                "project": {
                    "name": project_name,
                    "domain": {"id": project_domain_id},
                }
            },
        }
    }

    log.info(
        "authenticate: user=%s project=%s url=%s",
        username, project_name, url,
    )

    try:
        resp = requests.post(
            url,
            json=payload,
            timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT),
            headers={"Content-Type": "application/json"},
        )
    except requests.exceptions.RequestException as exc:
        log.warning("keystone unreachable: %s", exc)
        raise AuthenticationError(
            "Keystone identity service is not reachable. "
            "Contact your OpenStack administrator.",
            reason="keystone_unavailable",
        ) from exc

    if resp.status_code == 401:
        log.info("invalid credentials for user=%s", username)
        raise AuthenticationError(
            "Invalid username or password.",
            reason="invalid_credentials",
        )

    if resp.status_code == 404:
        log.warning(
            "project '%s' not found (or user has no access)", project_name,
        )
        raise AuthenticationError(
            f"Project '{project_name}' not found or access denied.",
            reason="invalid_credentials",
        )

    if resp.status_code >= 500:
        log.error("keystone returned %d: %s", resp.status_code, resp.text[:200])
        raise AuthenticationError(
            f"Keystone returned HTTP {resp.status_code}. Try again later.",
            reason="keystone_unavailable",
        )

    if resp.status_code != 201:
        log.error(
            "unexpected keystone status=%d body=%s",
            resp.status_code, resp.text[:200],
        )
        raise AuthenticationError(
            f"Unexpected Keystone response: HTTP {resp.status_code}.",
            reason="unexpected_response",
        )

    token = resp.headers.get("X-Subject-Token")
    if not token:
        log.error("keystone 201 but no X-Subject-Token header")
        raise AuthenticationError(
            "Keystone accepted credentials but returned no token.",
            reason="unexpected_response",
        )

    try:
        body = resp.json()
        token_info = body["token"]
        role_names = [r["name"] for r in token_info.get("roles", [])]
        claims = {
            "token":        token,
            "expires_at":   token_info["expires_at"],
            "username":     token_info["user"]["name"],
            "user_id":      token_info["user"]["id"],
            "project_name": token_info["project"]["name"],
            "project_id":   token_info["project"]["id"],
            "roles":        role_names,
        }
    except (KeyError, ValueError, TypeError) as exc:
        log.error("cannot parse keystone token response: %s", exc)
        raise AuthenticationError(
            "Keystone response shape is unexpected.",
            reason="unexpected_response",
        ) from exc

    # Authorization check — the role gate.
    if required_role not in role_names:
        log.info(
            "authz failed: user=%s has roles=%s (required=%s)",
            username, role_names, required_role,
        )
        raise AuthenticationError(
            f"Access denied. The '{required_role}' role is required "
            f"to use this dashboard. Your roles on project "
            f"'{project_name}' are: {', '.join(role_names) or '(none)'}.",
            reason="authorization_failure",
        )

    log.info(
        "authenticate OK: user=%s project=%s roles=%s expires=%s",
        claims["username"], claims["project_name"],
        role_names, claims["expires_at"],
    )
    return claims


def revoke_token(auth_url: str, token: str) -> None:
    """Revoke a Keystone token server-side (best effort).

    Keystone allows a user to revoke their own token by passing it
    as both X-Auth-Token (authorization) and X-Subject-Token (subject).
    Failures are logged but not raised — the caller must clear the
    session regardless.
    """
    if not token:
        return

    url = auth_url.rstrip("/") + _AUTH_TOKENS_PATH

    try:
        resp = requests.delete(
            url,
            timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT),
            headers={
                "X-Auth-Token":    token,
                "X-Subject-Token": token,
            },
        )
    except requests.exceptions.RequestException as exc:
        log.warning("token revocation HTTP error: %s", exc)
        return

    # 204 No Content = success; 404 = token already expired / revoked.
    if resp.status_code in (204, 404):
        log.info("token revoked (status=%d)", resp.status_code)
    else:
        log.warning(
            "token revocation unexpected status=%d body=%s",
            resp.status_code, resp.text[:120],
        )
