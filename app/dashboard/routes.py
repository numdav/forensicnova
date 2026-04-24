"""ForensicNova dashboard — HTTP route handlers.

Routes:
  GET  /dashboard/         -> home (login required) — FASE 5 step 2b placeholder
  GET  /dashboard/login    -> render login form
  POST /dashboard/login    -> validate form, auth to Keystone, set session
  GET  /dashboard/logout   -> revoke Keystone token, clear session

The blueprint uses its own templates/ folder, isolated from any other
template search path.  See app/dashboard/__init__.py for rationale.
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
# GET /dashboard/
# ---------------------------------------------------------------------------

@dashboard_bp.route("/")
@login_required
def home():
    """Post-login landing page (placeholder for FASE 5 step 2c)."""
    return render_template("home.html")


# ---------------------------------------------------------------------------
# GET  /dashboard/login
# POST /dashboard/login
# ---------------------------------------------------------------------------

@dashboard_bp.route("/login", methods=["GET", "POST"])
def login():
    """Render login form on GET; validate and issue a session on POST."""
    # Already logged in? Redirect to home instead of showing login again.
    if "keystone_token" in session:
        return redirect(url_for("dashboard.home"))

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
        return redirect(url_for("dashboard.home"))

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
