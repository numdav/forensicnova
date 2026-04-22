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
   - core_bp:    /health, /version (unauthenticated, root mount).
   - api_v1_bp:  /api/v1/* (Keystone-protected, DFIR REST API).

3. Logging
   - Dual sink: rotating file in cfg.log_dir AND stderr (journald captures
     stderr automatically when running under systemd).

4. Authentication (FASE 4)
   - keystonemiddleware.auth_token is wired around app.wsgi_app.
   - delay_auth_decision=True: the middleware never rejects a request on
     its own; it only POPULATES request.environ['HTTP_X_*'] with the
     validated identity (or marks it 'Invalid'/missing).  Each blueprint
     decides whether to enforce auth via its own before_request hook.
     This is what keeps /health unauthenticated while /api/v1/* is locked.
   - The middleware itself authenticates as a service user (admin) with
     enough privilege to validate arbitrary tokens against Keystone.
     User credentials come from the [keystone_authtoken] section of
     forensicnova.conf, written by devstack/plugin.sh.
"""
from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Optional

from flask import Flask

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


def _wrap_keystone_auth(app: Flask, cfg: Config) -> None:
    """Wrap app.wsgi_app with keystonemiddleware.auth_token.

    delay_auth_decision=True — never reject on its own, just populate
    HTTP_X_* environ keys.  Per-blueprint before_request hooks enforce
    the actual access policy.

    If [keystone_authtoken] is not configured (e.g. local dev without
    plugin.sh having run), we skip wiring and log a clear warning.  In
    that case /api/v1/* will return 401 because HTTP_X_IDENTITY_STATUS
    will never be 'Confirmed' — which is the safe default.
    """
    missing = [
        k for k in ("auth_url", "username", "password", "project_name")
        if not getattr(cfg, f"keystone_authtoken_{k}", None)
        and not (k == "auth_url" and cfg.keystone_auth_url)
    ]
    if missing:
        app.logger.warning(
            "keystonemiddleware NOT wired — missing config: %s. "
            "/api/v1/* will reject all requests.", missing,
        )
        return

    try:
        from keystonemiddleware import auth_token
    except ImportError as exc:
        app.logger.error(
            "keystonemiddleware not installed (%s) — auth disabled", exc,
        )
        return

    auth_conf = {
        "auth_type":           "password",
        "auth_url":            cfg.keystone_auth_url,
        "username":            cfg.keystone_authtoken_username,
        "password":            cfg.keystone_authtoken_password,
        "project_name":        cfg.keystone_authtoken_project,
        "user_domain_id":      "default",
        "project_domain_id":   "default",
        "delay_auth_decision": True,
        # Cache token validations in memory for 5 min — reduces load on
        # Keystone when the same operator makes multiple requests.
        "token_cache_time":    300,
    }
    app.wsgi_app = auth_token.AuthProtocol(app.wsgi_app, auth_conf)
    app.logger.info(
        "keystonemiddleware wired (service_user=%s, delay_auth_decision=True)",
        cfg.keystone_authtoken_username,
    )


def create_app(config: Optional[Config] = None) -> Flask:
    """Build and return a fully-configured Flask application."""
    app = Flask(__name__)
    cfg = config or load_config()

    app.config["FORENSICNOVA"] = cfg
    app.config["VERSION"] = __version__

    _configure_logging(app, cfg)

    # Register blueprints.  The import of app.api also imports app.api.v1
    # via the re-export at the bottom of app/api/__init__.py.
    from app.api import core_bp, api_v1_bp
    app.register_blueprint(core_bp)
    app.register_blueprint(api_v1_bp, url_prefix="/api/v1")

    # Wrap with Keystone middleware AFTER blueprints are registered so
    # the wsgi_app being wrapped is the fully-routed Flask dispatcher.
    _wrap_keystone_auth(app, cfg)

    app.logger.info(
        "ForensicNova %s initialized — bind %s:%d (config: %s)",
        __version__, cfg.bind_host, cfg.bind_port, cfg.config_path,
    )
    return app
