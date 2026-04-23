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

4. Authentication — Keystone middleware wiring (per official docs)
   - https://docs.openstack.org/keystonemiddleware/latest/middlewarearchitecture.html
   - AuthProtocol does NOT accept auth parameters as a raw dict.
     Supported patterns:
        (a) paste-deploy pipeline with [keystone_authtoken] INI loaded
            globally by oslo.config.
        (b) programmatic: build a ConfigOpts, load the INI file, then pass
            it as {"oslo_config_config": CONF} to AuthProtocol.
     We use pattern (b) because ForensicNova is a standalone Flask app.
   - IMPORTANT: we do NOT pre-register the middleware's own options
     (auth_type, auth_url, delay_auth_decision, ...).  The middleware
     registers them itself on the CONF we pass in, and pre-registering
     triggers DuplicateOptError.  We simply load the INI file and let
     the middleware find the values there.
   - delay_auth_decision=True is forced via set_override() AFTER the
     middleware has registered its options.  Policy: /health must stay
     unauthenticated; per-blueprint before_request hooks enforce auth.
   - The middleware authenticates as a service user (admin) with enough
     privilege to validate arbitrary tokens.  Credentials live in
     [keystone_authtoken] inside /etc/forensicnova/forensicnova.conf,
     written by devstack/plugin.sh.
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

    Pattern (b) from the module docstring:
      1. Build an empty oslo_config.cfg.ConfigOpts.
      2. Load our INI file into it (values stay unparsed until options
         are registered by someone — namely the middleware itself).
      3. Pass {"oslo_config_config": CONF} to AuthProtocol.  The
         middleware registers its opts on CONF and reads the values
         from [keystone_authtoken].
      4. Force delay_auth_decision=True via set_override().
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
        # The middleware will register [keystone_authtoken] opts on CONF
        # inside AuthProtocol.__init__ and then read them.
        app.wsgi_app = auth_token.AuthProtocol(
            app.wsgi_app,
            {"oslo_config_config": CONF},
        )
        # Force delay_auth_decision=True AFTER middleware registered opts.
        CONF.set_override(
            "delay_auth_decision", True, group="keystone_authtoken",
        )
    except Exception as exc:  # noqa: BLE001
        app.logger.exception(
            "failed to wire keystonemiddleware (%s) — auth disabled", exc,
        )
        return

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

    from app.api import core_bp, api_v1_bp
    app.register_blueprint(core_bp)
    app.register_blueprint(api_v1_bp, url_prefix="/api/v1")

    _wrap_keystone_auth(app, cfg)

    app.logger.info(
        "ForensicNova %s initialized — bind %s:%d (config: %s)",
        __version__, cfg.bind_host, cfg.bind_port, cfg.config_path,
    )
    return app
