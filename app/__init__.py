"""ForensicNova — Flask application package.

Exports:
    __version__ : str           — semantic version of the tool
    create_app(config) -> Flask — application factory

Design rationale:

1. Factory pattern (create_app)
   - Config is loaded lazily, at call time, not at module import time.
   - Tests can pass an ad-hoc Config without touching the filesystem.
   - No module-level side effects means safer imports from anywhere.

2. Blueprints
   - core_bp:       /health, /version    (unauthenticated, root mount).
   - api_v1_bp:     /api/v1/*             (Keystone X-Auth-Token, token-based).
   - dashboard_bp:  /dashboard/*          (Keystone session, cookie-based).

3. Logging
   - Dual sink: rotating file in cfg.log_dir AND stderr (journald captures
     stderr automatically when running under systemd).

4. Authentication — Keystone middleware wiring (per official docs)
   - https://docs.openstack.org/keystonemiddleware/latest/middlewarearchitecture.html
   - Pattern used: programmatic oslo.config.
       * Build an empty oslo_config.cfg.ConfigOpts.
       * Load the INI file — values stay unparsed until someone
         registers the options, which the middleware does in its __init__.
       * Pass {"oslo_config_config": CONF} to AuthProtocol.
   - IMPORTANT: we do NOT pre-register the middleware's own options.
     AuthProtocol.__init__ registers them itself on the CONF we pass in;
     pre-registering triggers DuplicateOptError.
   - IMPORTANT: delay_auth_decision and all other [keystone_authtoken]
     values MUST be set in the INI file before wrapping, because the
     middleware reads them during __init__.  set_override() after the
     fact has no effect on the already-initialised middleware instance.
   - Policy choice: delay_auth_decision=true is set in the INI so that
     /health stays unauthenticated (no token required) and each
     blueprint enforces auth via its own before_request hook.
   - The middleware authenticates as a service user (admin) with enough
     privilege to validate arbitrary tokens against Keystone.

5. Session & CSRF — FASE 5 dashboard infrastructure
   - SECRET_KEY is read from a file on disk (see _load_secret_key), not
     hardcoded and not env-var based.  Rationale: the key must persist
     across restarts (otherwise active browser sessions get invalidated
     on every restack) and must not be visible in /proc/<pid>/environ.
     The plugin.sh generates it at post-config time, mode 600, owned by
     the service user.
   - Session cookies are HttpOnly (blocks JS exfiltration) and SameSite=Lax
     (blocks basic CSRF).  Secure=False for dev (HTTP); flip to True in
     any HTTPS deployment.
   - PERMANENT_SESSION_LIFETIME=8h is a reasonable analyst-shift upper bound.
     Views that set session.permanent=True (login) activate this limit.
   - Flask-WTF CSRFProtect is initialised globally, then the API blueprints
     are EXEMPTED.  The API is consumed with X-Auth-Token by non-browser
     clients (curl, scripts, the dashboard itself via loopback) — CSRF
     tokens would break them.  Only the dashboard blueprint is actually
     CSRF-protected, since only it consumes HTML forms with cookie auth.
"""
from __future__ import annotations

import logging
import os
from datetime import timedelta
from logging.handlers import RotatingFileHandler
from typing import Optional

from flask import Flask
from flask_wtf.csrf import CSRFProtect

from app.config import Config, load_config

__version__ = "0.1.0"

_LOGGER_NAME = "forensicnova"


def _configure_logging(app: Flask, cfg: Config) -> None:
    """Wire up file + stderr logging on the 'forensicnova' logger."""
    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    root_logger = logging.getLogger(_LOGGER_NAME)
    root_logger.setLevel(logging.INFO)
    root_logger.handlers.clear()

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)
    stream_handler.setLevel(logging.INFO)
    root_logger.addHandler(stream_handler)

    try:
        os.makedirs(cfg.log_dir, exist_ok=True)
        log_path = os.path.join(cfg.log_dir, "forensicnova.log")
        file_handler = RotatingFileHandler(
            log_path, maxBytes=10 * 1024 * 1024, backupCount=5
        )
        file_handler.setFormatter(fmt)
        file_handler.setLevel(logging.INFO)
        root_logger.addHandler(file_handler)
        root_logger.info("file logging enabled at %s", log_path)
    except (PermissionError, OSError) as exc:
        root_logger.warning(
            "file logging disabled (%s): stderr only", exc
        )

    app.logger.handlers = root_logger.handlers
    app.logger.setLevel(logging.INFO)


def _load_secret_key(cfg: Config) -> bytes:
    """Read the Flask session signing key from disk.

    Fail-fast: if the file is missing, too short, or unreadable, the
    application must not start.  A silent fallback to a random key
    would invalidate all active dashboard sessions on every restart
    and give no indication of misconfiguration.
    """
    path = cfg.secret_key_path
    if not os.path.exists(path):
        raise RuntimeError(
            f"Flask secret_key file not found at {path!r}. "
            "Generate it with: "
            "openssl rand -hex 32 | sudo tee /var/lib/forensicnova/secret_key "
            "&& sudo chown stack:stack /var/lib/forensicnova/secret_key "
            "&& sudo chmod 600 /var/lib/forensicnova/secret_key. "
            "The DevStack plugin.sh post-config phase does this automatically."
        )
    with open(path, "rb") as fh:
        key = fh.read().strip()
    if len(key) < 32:
        raise RuntimeError(
            f"Flask secret_key at {path!r} is too short "
            f"({len(key)} bytes, want >= 32). Regenerate with: "
            "openssl rand -hex 32."
        )
    return key


def _configure_session(app: Flask, cfg: Config) -> None:
    """Set SECRET_KEY and session cookie hardening flags."""
    app.config["SECRET_KEY"] = _load_secret_key(cfg)

    # Cookie hardening — HttpOnly blocks document.cookie reads from XSS;
    # SameSite=Lax blocks CSRF from third-party form submissions.
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    # HTTP deployment (DevStack dev): Secure=False so the browser sends
    # the cookie over plain HTTP.  In any HTTPS deployment flip this to
    # True to pin the cookie to TLS channels.
    app.config["SESSION_COOKIE_SECURE"] = False

    # Upper bound on a forensic analyst's logged-in session.  Views that
    # want to activate this bound must set session.permanent = True.
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

    app.logger.info(
        "session configured: secret_key from %s (HttpOnly=True, SameSite=Lax, "
        "Secure=False [dev HTTP], lifetime=8h)",
        cfg.secret_key_path,
    )


def _wrap_keystone_auth(app: Flask, cfg: Config) -> None:
    """Wrap app.wsgi_app with keystonemiddleware.auth_token.

    Pattern (b) from the module docstring: build an oslo.config ConfigOpts,
    load the INI file, hand it to AuthProtocol via oslo_config_config.
    All middleware parameters (including delay_auth_decision) come from
    [keystone_authtoken] in the INI — do NOT try to override them
    programmatically after middleware instantiation.
    """
    missing = []
    if not cfg.keystone_authtoken_username:
        missing.append("keystone_authtoken.username")
    if not cfg.keystone_authtoken_password:
        missing.append("keystone_authtoken.password")
    if not cfg.keystone_authtoken_project:
        missing.append("keystone_authtoken.project_name")
    if not cfg.keystone_auth_url:
        missing.append("keystone.auth_url")

    if missing:
        app.logger.warning(
            "keystonemiddleware NOT wired — missing config: %s. "
            "/api/v1/* will reject all requests.", missing,
        )
        return

    try:
        from keystonemiddleware import auth_token
        from oslo_config import cfg as oslo_cfg
    except ImportError as exc:
        app.logger.error(
            "middleware dependency missing (%s) — auth disabled", exc,
        )
        return

    try:
        CONF = oslo_cfg.ConfigOpts()
        CONF(
            args=[],
            default_config_files=[cfg.config_path],
            project="forensicnova",
        )
        app.wsgi_app = auth_token.AuthProtocol(
            app.wsgi_app,
            {"oslo_config_config": CONF},
        )
    except Exception as exc:  # noqa: BLE001
        app.logger.exception(
            "failed to wire keystonemiddleware (%s) — auth disabled", exc,
        )
        return

    app.logger.info(
        "keystonemiddleware wired (service_user=%s)",
        cfg.keystone_authtoken_username,
    )


def create_app(config: Optional[Config] = None) -> Flask:
    """Build and return a fully-configured Flask application."""
    app = Flask(__name__)
    cfg = config or load_config()

    app.config["FORENSICNOVA"] = cfg
    app.config["VERSION"] = __version__

    _configure_logging(app, cfg)
    _configure_session(app, cfg)

    from app.api import core_bp, api_v1_bp
    from app.dashboard import dashboard_bp

    app.register_blueprint(core_bp)
    app.register_blueprint(api_v1_bp, url_prefix="/api/v1")
    app.register_blueprint(dashboard_bp, url_prefix="/dashboard")

    # CSRF protection — global init, then exempt the token-authenticated API
    # blueprints.  Non-browser clients (curl, scripts, the dashboard via
    # loopback with X-Auth-Token) must not be forced to carry a CSRF token.
    # dashboard_bp is deliberately NOT exempted — its HTML forms carry a
    # CSRF token via {{ form.hidden_tag() }}.
    csrf = CSRFProtect(app)
    csrf.exempt(core_bp)
    csrf.exempt(api_v1_bp)
    app.extensions["csrf"] = csrf  # store for later reference if needed

    _wrap_keystone_auth(app, cfg)

    app.logger.info(
        "ForensicNova %s initialized — bind %s:%d (config: %s)",
        __version__, cfg.bind_host, cfg.bind_port, cfg.config_path,
    )
    return app
