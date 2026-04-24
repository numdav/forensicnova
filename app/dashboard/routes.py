"""ForensicNova dashboard — HTTP route handlers.

Routes:
  GET  /dashboard/         -> acquisitions list (login required) — the home
  GET  /dashboard/login    -> render login form
  POST /dashboard/login    -> validate form, auth to Keystone, set session
  GET  /dashboard/logout   -> revoke Keystone token, clear session

Error handling — blueprint-level, centralized:
  SessionRevokedError  -> clear session + flash + redirect to /login
  ApiUnavailableError  -> flash banner + render page with empty data, HTTP 503

The error handlers live on the blueprint, so any view can raise the
typed exceptions (via api_client) without try/except — Flask routes the
exception to the right handler automatically.
"""
from __future__ import annotations

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    session,
    url_for,
)

from app.dashboard.api_client import (
    ApiUnavailableError,
    SessionRevokedError,
    list_acquisitions,
)
from app.dashboard.decorators import login_required
from app.dashboard.forms import LoginForm
from app.dashboard.keystone_auth import (
    AuthenticationError,
    authenticate,
    revoke_token,
)

dashboard_bp = Blueprint(
    "dashboard",
    __name__,
    template_folder="templates",
)


# ---------------------------------------------------------------------------
# Blueprint-level error handlers
# ---------------------------------------------------------------------------

@dashboard_bp.errorhandler(SessionRevokedError)
def _handle_session_revoked(exc: SessionRevokedError):
    """Token was rejected mid-session — clear cookie and redirect to login."""
    current_app.logger.info(
        "session revoked mid-request: user=%s",
        session.get("username", "unknown"),
    )
    session.clear()
    flash(
        "Your authentication was revoked. Please sign in again.",
        "warning",
    )
    return redirect(url_for("dashboard.login"))


@dashboard_bp.errorhandler(ApiUnavailableError)
def _handle_api_unavailable(exc: ApiUnavailableError):
    """Loopback API is down — render the page frame with empty data."""
    current_app.logger.error("api unavailable: %s", exc)
    flash(
        "The forensic API is temporarily unavailable. "
        "Try again in a moment.",
        "danger",
    )
    # Keep the UI shell usable — the navbar and logout still work,
    # only the data section renders empty.
    return render_template(
        "acquisitions_list.html",
        acquisitions=[],
        count=0,
        api_down=True,
    ), 503


# ---------------------------------------------------------------------------
# GET /dashboard/   — acquisitions list (home)
# ---------------------------------------------------------------------------

@dashboard_bp.route("/")
@login_required
def acquisitions_list():
    """Home — table of all acquisitions.

    Feeds from GET /api/v1/acquisitions/ via the loopback client.
    Exceptions propagate to the blueprint errorhandlers above — no try/except.
    """
    result = list_acquisitions()
    return render_template(
        "acquisitions_list.html",
        acquisitions=result.get("acquisitions", []),
        count=result.get("count", 0),
        api_down=False,
    )


# ---------------------------------------------------------------------------
# GET  /dashboard/login
# POST /dashboard/login
# ---------------------------------------------------------------------------

@dashboard_bp.route("/login", methods=["GET", "POST"])
def login():
    """Render login form on GET; validate and issue a session on POST."""
    # Already logged in? Redirect to home instead of showing login again.
    if "keystone_token" in session:
        return redirect(url_for("dashboard.acquisitions_list"))

    form = LoginForm()

    if form.validate_on_submit():
        cfg = current_app.config["FORENSICNOVA"]

        try:
            claims = authenticate(
                auth_url=cfg.keystone_auth_url,
                username=form.username.data,
                password=form.password.data,
                project_name=cfg.forensics_project,
                required_role=cfg.keystone_forensic_role,
            )
        except AuthenticationError as exc:
            current_app.logger.info(
                "dashboard login denied: user=%s reason=%s",
                form.username.data, exc.reason,
            )
            flash(str(exc), "danger")
            return render_template("login.html", form=form)
        except Exception:  # noqa: BLE001 — belt-and-suspenders
            current_app.logger.exception(
                "unexpected error during dashboard login",
            )
            flash(
                "Unexpected error during authentication. "
                "Check service logs.",
                "danger",
            )
            return render_template("login.html", form=form)

        # Install the session.  .permanent = True activates the 8h
        # lifetime from PERMANENT_SESSION_LIFETIME.
        session.permanent = True
        session["keystone_token"] = claims["token"]
        session["username"]       = claims["username"]
        session["user_id"]        = claims["user_id"]
        session["project_name"]   = claims["project_name"]
        session["project_id"]     = claims["project_id"]
        session["expires_at"]     = claims["expires_at"]
        session["roles"]          = claims["roles"]

        current_app.logger.info(
            "dashboard login OK: user=%s project=%s",
            claims["username"], claims["project_name"],
        )
        flash(f"Welcome, {claims['username']}.", "success")
        return redirect(url_for("dashboard.acquisitions_list"))

    return render_template("login.html", form=form)


# ---------------------------------------------------------------------------
# GET /dashboard/logout
# ---------------------------------------------------------------------------

@dashboard_bp.route("/logout")
def logout():
    """Revoke the Keystone token server-side and clear the session."""
    token    = session.get("keystone_token")
    username = session.get("username", "unknown")
    cfg      = current_app.config["FORENSICNOVA"]

    if token:
        try:
            revoke_token(cfg.keystone_auth_url, token)
        except Exception:  # noqa: BLE001
            current_app.logger.exception(
                "token revocation raised — clearing session anyway",
            )

    session.clear()
    current_app.logger.info("dashboard logout: user=%s", username)
    flash("You have been signed out.", "info")
    return redirect(url_for("dashboard.login"))
