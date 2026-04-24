"""ForensicNova dashboard — auth decorators.

@login_required guards routes that require a valid Keystone session.

Semantics:
  - If session has no 'keystone_token' -> redirect to login with a flash.
  - If session token is past its expires_at -> clear session, redirect with flash.
  - Otherwise -> pass through to the view.

Note: we do NOT re-validate the token against Keystone on every request
(that would be a round-trip per click).  We trust the client-side cookie
signature (HMAC over app.secret_key) as proof of session authenticity,
and we respect the expires_at that Keystone gave us at login time.

If a token is revoked mid-session (e.g. by an admin), the next API call
the dashboard makes to /api/v1/* with that token will fail with 401,
and we handle that there — not here.
"""
from __future__ import annotations

from datetime import datetime, timezone
from functools import wraps

from flask import current_app, flash, redirect, session, url_for


def login_required(view_func):
    """Redirect to /dashboard/login if no valid Keystone session."""

    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if "keystone_token" not in session:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("dashboard.login"))

        expires_at = session.get("expires_at")
        if expires_at and _is_expired(expires_at):
            current_app.logger.info(
                "session expired for user=%s — clearing and redirecting",
                session.get("username", "unknown"),
            )
            session.clear()
            flash("Your session has expired. Please sign in again.", "warning")
            return redirect(url_for("dashboard.login"))

        return view_func(*args, **kwargs)

    return wrapper


def _is_expired(expires_at_iso: str) -> bool:
    """Return True if the given ISO-8601 UTC timestamp is in the past."""
    try:
        # Keystone returns '2026-04-24T16:07:42.000000Z' style timestamps.
        normalized = expires_at_iso.replace("Z", "+00:00")
        exp = datetime.fromisoformat(normalized)
    except (ValueError, AttributeError):
        # If we can't parse it, treat as expired — safe default.
        return True
    return datetime.now(timezone.utc) >= exp
