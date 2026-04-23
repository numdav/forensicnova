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
     The supported patterns are:
        (a) paste-deploy pipeline with [keystone_authtoken] in an INI file
            loaded globally by oslo.config.
        (b) programmatic: build an oslo_config.cfg.ConfigOpts, register the
            middleware options on it, load the INI file, then pass it as
            {"oslo_config_config": CONF} to AuthProtocol.
     We use pattern (b) because ForensicNova is a standalone Flask app,
     not a paste-deploy pipeline like legacy Nova/Swift.
   - delay_auth_decision=True: the middleware never rejects a request on
     its own; it only populates request.environ['HTTP_X_*'] with the
     validated identity (or marks it 'Invalid'/missing).  Each blueprint
     decides whether to enforce auth via its own before_request hook.
     This is what keeps /health unauthenticated while /api/v1/* is locked.
   - The middleware itself authenticates as a service user (admin) with
     enough privilege to validate arbitrary tokens against Keystone.
     Credentials live in [keystone_authtoken] inside
     /etc/forensicnova/forensicnova.conf, written by devstack/plugin.sh.
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


def _build_oslo_conf(cfg: Config):
    """Build an oslo.config ConfigOpts for keystonemiddleware.

    Registers the subset of [keystone_authtoken] options we actually use
    (the middleware itself would register many more via list_auth_token_opts,
    but the minimal set below is sufficient for validating tokens against
    Keystone in password auth mode).

    Returns the loaded CONF object, or None if registration/loading fails.
    """
    from oslo_config import cfg as oslo_cfg

    CONF = oslo_cfg.ConfigOpts()

    # Options documented at:
    # https://docs.openstack.org/keystonemiddleware/latest/middlewarearchitecture.html
    authtoken_opts = [
        oslo_cfg.StrOpt("auth_type"),
        oslo_cfg.StrOpt("auth_url"),
        oslo_cfg.StrOpt("username"),
        oslo_cfg.StrOpt("password", secret=True),
        oslo_cfg.StrOpt("project_name"),
        oslo_cfg.StrOpt("user_domain_id"),
        oslo_cfg.StrOpt("project_domain_id"),
        oslo_cfg.BoolOpt("delay_auth_decision", default=False),
        oslo_cfg.IntOpt("token_cache_time", default=300),
    ]
    CONF.register_opts(authtoken_opts, group="keystone_authtoken")

    # Load the ForensicNova INI file (same one that populated cfg).
    # oslo.config reads values by section/key; our file already has the
    # correct [keystone_authtoken] section written by plugin.sh.
    CONF(
        args=[],
        default_config_files=[cfg.config_path],
        project="forensicnova",
        validate_default_values=True,
    )

    # Force delay_auth_decision=True regardless of file setting.
    # This is ForensicNova policy: /health must stay unauthenticated, and
    # we enforce auth per-blueprint in before_request hooks.
    CONF.set_override("delay_auth_decision", True, group="keystone_authtoken")

    return CONF


def _wrap_keystone_auth(app: Flask, cfg: Config) -> None:
    """Wrap app.wsgi_app with keystonemiddleware.auth_token.

    Pattern (b) from the module docstring: pass an oslo.config ConfigOpts
    via {"oslo_config_config": CONF} so the middleware reads all its
    parameters from the same INI file as the rest of ForensicNova.
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
    except ImportError as exc:
        app.logger.error(
            "keystonemiddleware not installed (%s) — auth disabled", exc,
        )
        return

    try:
        CONF = _build_oslo_conf(cfg)
    except Exception as exc:  # noqa: BLE001 — log and bail out
        app.logger.error(
            "failed to build oslo.config for auth_token: %s — auth disabled",
            exc,
        )
        return

    # The only keys AuthProtocol accepts in its dict are operational hints;
    # actual parameters come from CONF.
    middleware_conf = {
        "oslo_config_config": CONF,
    }
    app.wsgi_app = auth_token.AuthProtocol(app.wsgi_app, middleware_conf)
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
