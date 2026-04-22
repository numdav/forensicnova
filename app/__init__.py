"""ForensicNova — Flask application package.

Exports:
    __version__ : str           — semantic version of the tool
    create_app(config) -> Flask — application factory

Design rationale (kept short because it will be defended orally):

1. Factory pattern (create_app)
   - Config is loaded lazily, at call time, not at module import time.
   - Tests can pass an ad-hoc Config without touching the filesystem.
   - No module-level side effects means safer imports from anywhere
     (including unit tests and future CLI helpers).

2. Blueprints
   - Each feature area is a Flask blueprint registered here.
   - FASE 3 registers only `core_bp` (liveness / version).
   - FASE 4 will add `api_v1_bp` under /api/v1 (memory_acquire, listing,
     report download) protected by keystonemiddleware.
   - FASE 5+ (thesis) will add `dashboard_bp` (Horizon-independent UI)
     and possibly `ioc_bp` for Volatility/YARA endpoints.

3. Logging
   - Dual sink: rotating file in cfg.log_dir AND stderr.
   - Stderr is captured by systemd/journald -> ops-friendly.
   - File in log_dir is the audit trail (who/when/what at the tool
     level); in FASE 4+ forensic operations will log through this same
     handler so chain-of-custody events are persisted even if journald
     is rotated.
"""
from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Optional

from flask import Flask

from app.config import Config, load_config

__version__ = "0.1.0"

# Single module-level logger used also by sub-packages via getLogger(__name__).
_LOGGER_NAME = "forensicnova"


def _configure_logging(app: Flask, cfg: Config) -> None:
    """Wire up file + stderr logging on the 'forensicnova' logger.

    The Flask app logger is redirected to the same logger so that
    `app.logger.info(...)` and `logging.getLogger("forensicnova.xxx")`
    converge on the same handlers — one place to rule them all.
    """
    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    root_logger = logging.getLogger(_LOGGER_NAME)
    root_logger.setLevel(logging.INFO)
    # Avoid duplicate handlers if create_app is called twice (tests).
    root_logger.handlers.clear()

    # Stderr handler (always present -> journald captures it).
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)
    stream_handler.setLevel(logging.INFO)
    root_logger.addHandler(stream_handler)

    # File handler: best-effort. If log_dir is not writable (dev box,
    # tests) we log a warning via stderr and carry on.
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

    # Redirect Flask's own logger to ours.
    app.logger.handlers = root_logger.handlers
    app.logger.setLevel(logging.INFO)


def create_app(config: Optional[Config] = None) -> Flask:
    """Build and return a fully-configured Flask application.

    :param config: optional pre-built Config (tests / alternative paths).
                   When None, reads /etc/forensicnova/forensicnova.conf.
    """
    app = Flask(__name__)
    cfg = config or load_config()

    # Expose Config and version to the whole app via app.config — the
    # Flask-idiomatic way to share immutable data across blueprints.
    app.config["FORENSICNOVA"] = cfg
    app.config["VERSION"] = __version__

    _configure_logging(app, cfg)

    # Register blueprints. Order is not meaningful, but keep root-level
    # (unauthenticated) endpoints first for readability.
    from app.api import core_bp
    app.register_blueprint(core_bp)

    app.logger.info(
        "ForensicNova %s initialized — will bind to %s:%d (config: %s)",
        __version__, cfg.bind_host, cfg.bind_port, cfg.config_path,
    )
    return app
