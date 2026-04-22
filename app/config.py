"""ForensicNova configuration loader.

Reads the INI file written by devstack/plugin.sh at stack time
(default path: /etc/forensicnova/forensicnova.conf) and exposes
a Config dataclass consumed by the Flask application factory.

Why stdlib configparser:
- Zero external dependencies.
- INI is the native OpenStack config format (nova.conf, keystone.conf, ...),
  keeping ForensicNova aligned with the ecosystem.
- Easy to upgrade to oslo.config in the future without changing the file
  format on disk (the plugin keeps writing INI).

The Config dataclass intentionally holds plain Python defaults: if a
section or key is missing, the app still starts. This helps during
development and allows running `python -m app.wsgi` on a dev box without
the plugin having written the file yet.
"""
from __future__ import annotations

import configparser
import os
from dataclasses import dataclass
from typing import Optional

DEFAULT_CONFIG_PATH = "/etc/forensicnova/forensicnova.conf"


@dataclass
class Config:
    """Typed view of forensicnova.conf.

    Field groups mirror the INI sections written by plugin.sh.
    Extend this dataclass (and load_config below) when FASE 4+
    introduces new configuration sections (e.g. [volatility],
    [yara], [misp] for the thesis work).
    """

    # [DEFAULT] — runtime / bind
    bind_host: str = "0.0.0.0"
    bind_port: int = 5234
    work_dir: str = "/var/lib/forensicnova"
    log_dir: str = "/var/log/forensicnova"

    # [keystone] — identity integration (used in FASE 4 by keystonemiddleware)
    keystone_auth_url: str = ""
    keystone_region: str = "RegionOne"
    keystone_forensic_role: str = "forensic_analyst"

    # [swift] — object storage for dumps + chain-of-custody artifacts
    swift_container: str = "forensics"

    # [forensics] — DFIR project context
    forensics_project: str = "forensics"
    forensics_dfir_user: str = "dfir-tester"

    # [libvirt] — hypervisor connection for virsh dump (FASE 4)
    libvirt_uri: str = "qemu:///system"

    # Where this config was actually loaded from (useful for diagnostics)
    config_path: str = DEFAULT_CONFIG_PATH


def load_config(path: Optional[str] = None) -> Config:
    """Load ForensicNova config from an INI file.

    Resolution order for the file path:
      1. Explicit `path` argument (used in tests).
      2. FORENSICNOVA_CONFIG environment variable.
      3. DEFAULT_CONFIG_PATH (production / DevStack).

    Missing file or missing keys fall back to dataclass defaults — the
    app will log a warning but still start. This is a deliberate
    dev-friendliness choice; in FASE 4 we may switch to strict loading
    for the forensics sections that have no sensible default.
    """
    cfg_path = path or os.environ.get("FORENSICNOVA_CONFIG", DEFAULT_CONFIG_PATH)

    cp = configparser.ConfigParser()
    # Preserve key case (configparser lowercases by default).
    cp.optionxform = str
    read_files = cp.read(cfg_path)

    cfg = Config(config_path=cfg_path)

    # Note on [DEFAULT]: configparser treats DEFAULT values as inherited
    # by every other section. We only use it here for truly global
    # runtime knobs (bind_host, bind_port, log_dir, work_dir) — this is
    # exactly how the plugin writes the file, so semantics match.
    if read_files:
        cfg.bind_host = cp.get("DEFAULT", "bind_host", fallback=cfg.bind_host)
        cfg.bind_port = cp.getint("DEFAULT", "bind_port", fallback=cfg.bind_port)
        cfg.work_dir = cp.get("DEFAULT", "work_dir", fallback=cfg.work_dir)
        cfg.log_dir = cp.get("DEFAULT", "log_dir", fallback=cfg.log_dir)

    if cp.has_section("keystone"):
        cfg.keystone_auth_url = cp.get(
            "keystone", "auth_url", fallback=cfg.keystone_auth_url
        )
        cfg.keystone_region = cp.get(
            "keystone", "region_name", fallback=cfg.keystone_region
        )
        cfg.keystone_forensic_role = cp.get(
            "keystone", "forensic_role", fallback=cfg.keystone_forensic_role
        )

    if cp.has_section("swift"):
        cfg.swift_container = cp.get(
            "swift", "container", fallback=cfg.swift_container
        )

    if cp.has_section("forensics"):
        cfg.forensics_project = cp.get(
            "forensics", "project", fallback=cfg.forensics_project
        )
        cfg.forensics_dfir_user = cp.get(
            "forensics", "dfir_user", fallback=cfg.forensics_dfir_user
        )

    if cp.has_section("libvirt"):
        cfg.libvirt_uri = cp.get("libvirt", "uri", fallback=cfg.libvirt_uri)

    return cfg
