"""ForensicNova dashboard — HTTP route handlers."""
from __future__ import annotations

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    redirect,
    render_template,
    session,
    stream_with_context,
    url_for,
)

from app.dashboard.api_client import (
    AcquisitionError,
    ApiForbiddenError,
    ApiNotFoundError,
    ApiUnavailableError,
    SessionRevokedError,
    get_acquisition,
    list_acquisitions,
    list_servers,
    stream_dump,
    stream_report,
    trigger_acquisition,
)
from app.dashboard.decorators import login_required
from app.dashboard.forms import AcquireForm, LoginForm
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


@dashboard_bp.errorhandler(ApiForbiddenError)
def _handle_api_forbidden(exc: ApiForbiddenError):
    current_app.logger.info(
        "api forbidden mid-request: user=%s",
        session.get("username", "unknown"),
    )
    flash(
        "Access denied by the API. The forensic_analyst role may have "
        "been removed from your account. Contact your administrator.",
        "danger",
    )
    return redirect(url_for("dashboard.acquisitions_list"))


@dashboard_bp.errorhandler(ApiNotFoundError)
def _handle_api_not_found(exc: ApiNotFoundError):
    current_app.logger.info("api 404: %s", exc)
    flash(
        "The requested acquisition was not found. It may have been "
        "removed from Swift, or the link is stale.",
        "warning",
    )
    return redirect(url_for("dashboard.acquisitions_list"))


@dashboard_bp.errorhandler(AcquisitionError)
def _handle_acquisition_failed(exc: AcquisitionError):
    current_app.logger.error("acquisition failed: %s | detail=%s", exc, exc.detail)
    detail_reason = exc.detail.get("error", "unknown_error")
    flash(
        f"Acquisition failed: {exc} (reason: {detail_reason}). "
        "See service logs for full diagnostic output.",
        "danger",
    )
    return redirect(url_for("dashboard.acquire"))


@dashboard_bp.errorhandler(ApiUnavailableError)
def _handle_api_unavailable(exc: ApiUnavailableError):
    current_app.logger.error("api unavailable: %s", exc)
    flash(
        "The forensic API is temporarily unavailable. "
        "Try again in a moment.",
        "danger",
    )
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
    result = list_acquisitions()
    return render_template(
        "acquisitions_list.html",
        acquisitions=result.get("acquisitions", []),
        count=result.get("count", 0),
        api_down=False,
    )


# ---------------------------------------------------------------------------
# GET /dashboard/acquisitions/<id>   — detail page
# ---------------------------------------------------------------------------

@dashboard_bp.route("/acquisitions/<acquisition_id>")
@login_required
def acquisition_detail(acquisition_id: str):
    report = get_acquisition(acquisition_id)
    return render_template("acquisition_detail.html", report=report)


# ---------------------------------------------------------------------------
# GET /dashboard/acquisitions/<id>/download_dump
# GET /dashboard/acquisitions/<id>/download_report
# ---------------------------------------------------------------------------

@dashboard_bp.route("/acquisitions/<acquisition_id>/download_dump")
@login_required
def download_dump(acquisition_id: str):
    """Stream the .raw dump from Swift through the API to the browser."""
    current_app.logger.info(
        "dashboard download_dump: user=%s acq=%s",
        session.get("username", "unknown"), acquisition_id,
    )
    filename, content_length, chunks = stream_dump(acquisition_id)

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Content-Type-Options": "nosniff",
    }
    if content_length:
        headers["Content-Length"] = content_length

    return Response(
        stream_with_context(chunks),
        mimetype="application/octet-stream",
        headers=headers,
    )


@dashboard_bp.route("/acquisitions/<acquisition_id>/download_report")
@login_required
def download_report(acquisition_id: str):
    """Download the JSON report as attachment (served by the API)."""
    current_app.logger.info(
        "dashboard download_report: user=%s acq=%s",
        session.get("username", "unknown"), acquisition_id,
    )
    filename, content_length, chunks = stream_report(acquisition_id)

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Content-Type-Options": "nosniff",
    }
    if content_length:
        headers["Content-Length"] = content_length

    return Response(
        stream_with_context(chunks),
        mimetype="application/json",
        headers=headers,
    )


# ---------------------------------------------------------------------------
# GET  /dashboard/acquire   — render the trigger form
# POST /dashboard/acquire   — fire the acquisition
# ---------------------------------------------------------------------------

@dashboard_bp.route("/acquire", methods=["GET", "POST"])
@login_required
def acquire():
    servers_resp = list_servers()
    servers = servers_resp.get("servers", [])

    active   = [s for s in servers if s.get("status") == "ACTIVE"]
    inactive = [s for s in servers if s.get("status") != "ACTIVE"]

    def _label(s: dict) -> str:
        return "{name} | project:{proj} | {ram} MB | {status}".format(
            name=s.get("name") or "(unnamed)",
            proj=(s.get("project_id") or "?")[:8],
            ram=s.get("ram_mb") if s.get("ram_mb") is not None else "?",
            status=s.get("status") or "?",
        )

    choices = [(s["id"], _label(s)) for s in active + inactive]

    form = AcquireForm()
    form.instance_id.choices = choices

    if form.validate_on_submit():
        target_id = form.instance_id.data

        picked = next((s for s in servers if s["id"] == target_id), None)
        if not picked:
            flash("Selected VM is no longer present. Refresh the list.", "warning")
            return redirect(url_for("dashboard.acquire"))
        if picked.get("status") != "ACTIVE":
            flash(
                f"Cannot acquire RAM from '{picked.get('name')}' — "
                f"VM status is {picked.get('status')}, must be ACTIVE.",
                "warning",
            )
            return redirect(url_for("dashboard.acquire"))

        current_app.logger.info(
            "dashboard acquire: user=%s target=%s (%s)",
            session.get("username", "unknown"),
            target_id, picked.get("name"),
        )

        result = trigger_acquisition(target_id)

        acq_id = result.get("acquisition_id")
        vm_name = result.get("instance_name") or picked.get("name")
        size_mb = (result.get("size_bytes") or 0) / 1024 / 1024
        flash(
            f"Acquisition completed for {vm_name}: "
            f"{size_mb:.1f} MB, MD5 {result.get('md5', '?')[:12]}… "
            f"(integrity: {'verified' if result.get('etag_verified') else 'FAILED'}).",
            "success",
        )
        return redirect(url_for("dashboard.acquisition_detail", acquisition_id=acq_id))

    return render_template(
        "acquire_form.html",
        form=form,
        servers=servers,
        active_count=len(active),
        total_count=len(servers),
    )


# ---------------------------------------------------------------------------
# GET  /dashboard/login
# POST /dashboard/login
# ---------------------------------------------------------------------------

@dashboard_bp.route("/login", methods=["GET", "POST"])
def login():
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
        except Exception:  # noqa: BLE001
            current_app.logger.exception(
                "unexpected error during dashboard login",
            )
            flash(
                "Unexpected error during authentication. "
                "Check service logs.",
                "danger",
            )
            return render_template("login.html", form=form)

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
