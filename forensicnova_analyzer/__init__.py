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

    # Blueprint registration.
    # Lazy import to avoid cycles with future modules that may end up
    # importing the top-level package.
    from forensicnova_analyzer.api import core_bp, api_v1_bp

    app.register_blueprint(core_bp)
    app.register_blueprint(api_v1_bp, url_prefix="/api/v1")

    log.info("create_app() — blueprints registered: core, api_v1")
    return app
