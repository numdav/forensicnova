"""
forensicnova_analyzer — Flask backend for forensic memory dump analysis.

This package provides the SECOND Flask service of the project (separate
from the acquisition backend in `app/`):

  - Acquisition backend (app/, port 5234): libvirt coreDump, hashing,
    Swift upload, report generation.
  - Analyzer backend (this, port 5235): Swift dump download, analysis
    via Volatility 3 / YARA / MISP, JSON analysis upload.

Architectural rationale for the split:
  1. Crash isolation — a Volatility plugin that blows up (OOM, exception)
     kills the analyzer subprocess only, not the acquisition backend.
  2. Different workloads — acquisition is I/O-bound; analyzer is CPU+RAM
     bound (multi-GB memory scans). Independent resource tuning.
  3. Independent lifecycle — frequent analyzer restarts (work in progress
     for the thesis) must not interrupt in-flight acquisitions.

The `create_app()` factory pattern keeps the app non-singleton at module
load time, which simplifies testing and config separation.

This scaffolding commit registers only:
  - core_bp with /health, /version (unauthenticated endpoints)
  - api_v1_bp stub (empty, to be populated in subsequent commits)

The following are intentionally ABSENT in this first deploy:
  - keystonemiddleware (added when api_v1_bp grows authenticated
    endpoints like POST /analyses/<acq_id>)
  - JobManager (added in scaffolding phase 2 — async pipeline)
  - Swift client (added when dump download is implemented)
  - Volatility wrapper (added in scaffolding phase 3)
"""

import logging
import logging.handlers
import os
from pathlib import Path

from flask import Flask

from forensicnova_analyzer.config import AnalyzerConfig, load_config

__version__ = "0.1.0"

log = logging.getLogger(__name__)


def _init_logging(cfg: AnalyzerConfig) -> None:
    """Configure application logging.

    Two handlers:
      - RotatingFileHandler on cfg.log_file (10 MB x 5 files = 50 MB max)
      - StreamHandler on stderr (captured by systemd journal)

    Level configurable from the config file (default INFO).
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, cfg.log_level.upper(), logging.INFO))

    # Drop any pre-existing handlers (helpful during testing / reload).
    for handler in list(root.handlers):
        root.removeHandler(handler)

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    # File handler with rotation.
    log_dir = Path(cfg.log_file).parent
    log_dir.mkdir(parents=True, exist_ok=True)
    file_handler = logging.handlers.RotatingFileHandler(
        cfg.log_file,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)

    # Stderr handler — captured by systemd journal in production.
    stderr_handler = logging.StreamHandler()
    stderr_handler.setFormatter(fmt)
    root.addHandler(stderr_handler)

    log.info("logging initialised — level=%s file=%s", cfg.log_level, cfg.log_file)


def create_app(config_path: str | None = None) -> Flask:
    """Flask factory.

    config_path:
        Path to the INI configuration file. If None, it is read from the
        FORENSICNOVA_ANALYZER_CONFIG env var, with fallback to
        /etc/forensicnova/forensicnova-analyzer.conf.
    """
    if config_path is None:
        config_path = os.environ.get(
            "FORENSICNOVA_ANALYZER_CONFIG",
            "/etc/forensicnova/forensicnova-analyzer.conf",
        )

    cfg = load_config(config_path)
    _init_logging(cfg)
    log.info("create_app() — config=%s version=%s", config_path, __version__)

    app = Flask(__name__)
    app.config["FORENSICNOVA_ANALYZER"] = cfg
    app.config["VERSION"] = __version__

    # JobManager singleton — single instance shared by all endpoints.
    # recover_on_startup() must run at app start, NOT per-request: it
    # sweeps orphan jobs (left in pending/running by a service crash or
    # restart) and marks them as failed once. Putting it inside an
    # endpoint would re-run it on every HTTP call, costing disk I/O
    # and potentially racing with active workers.
    from forensicnova_analyzer.jobs import JobManager
    jobs_mgr = JobManager(cfg.jobs_dir)
    recovered = jobs_mgr.recover_on_startup()
    if recovered:
        log.warning(
            "create_app() — recovered %d orphan analyzer job(s)",
            recovered,
        )
    app.config["JOB_MANAGER"] = jobs_mgr

    # Wrap WSGI app with keystonemiddleware.auth_token. After this call
    # every request hits AuthProtocol BEFORE Flask routing, and the
    # token is validated. Then Flask runs, and individual blueprints
    # decide whether to enforce auth (api_v1_bp does via before_request;
    # core_bp does not, so /health and /version stay open).
    _wrap_keystone_auth(app, cfg)

    # Blueprint registration.
    # Lazy import to avoid cycles with future modules that may end up
    # importing the top-level package.
    from forensicnova_analyzer.api import core_bp, api_v1_bp

    app.register_blueprint(core_bp)
    app.register_blueprint(api_v1_bp, url_prefix="/api/v1")

    log.info("create_app() — blueprints registered: core, api_v1")
    return app


def _wrap_keystone_auth(app: Flask, cfg: AnalyzerConfig) -> None:
    """Wrap app.wsgi_app with keystonemiddleware.auth_token.

    Same pattern as app/__init__.py:_wrap_keystone_auth in the
    acquisition backend: build an oslo.config ConfigOpts loaded from
    the analyzer's INI file, hand it to AuthProtocol via
    oslo_config_config. All middleware parameters (including
    delay_auth_decision) come from [keystone_authtoken] in the INI —
    do NOT try to override them programmatically.

    The decision to enforce auth on individual routes lives in
    api/v1.py via a blueprint-level before_request handler. core_bp
    routes (/health, /version) are not under api_v1_bp and therefore
    remain unauthenticated for systemd probes and external monitoring.

    If any required identity configuration is missing the wrap is
    skipped and a warning is logged — the service still boots but
    every authenticated endpoint will reject with 401.
    """
    missing: list[str] = []
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
            "Authenticated endpoints will reject all requests.", missing,
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

    # Resolve the config file path: load_config() didn't record it on
    # the dataclass (frozen=True; we'd have to add a field), so read
    # the env var that drives create_app(). Default matches the
    # production deploy path the DevStack plugin writes to.
    config_path = os.environ.get(
        "FORENSICNOVA_ANALYZER_CONFIG",
        "/etc/forensicnova/forensicnova-analyzer.conf",
    )

    try:
        CONF = oslo_cfg.ConfigOpts()
        CONF(
            args=[],
            default_config_files=[config_path],
            project="forensicnova-analyzer",
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
        "keystonemiddleware wired (service_user=%s, config=%s)",
        cfg.keystone_authtoken_username, config_path,
    )
