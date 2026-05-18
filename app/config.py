"""ForensicNova configuration loader.

Reads the INI file written by devstack/plugin.sh at stack time
(default path: /etc/forensicnova/forensicnova.conf) and exposes
a Config dataclass consumed by the Flask application factory.

INI sections handled:
    [DEFAULT]            runtime / bind
    [keystone]           identity discovery (auth_url, region, role)
    [keystone_authtoken] service credentials for keystonemiddleware
    [swift]              object storage container name + SLO segment size
    [forensics]          DFIR project context
    [libvirt]            hypervisor connection URI
    [jobs]               async job manager

Sensitive values:
  - keystone_authtoken_password: read from the INI file (mode 640 stack:stack)
    OR overridden by the FORENSICNOVA_KEYSTONE_AUTHTOKEN_PASSWORD env var if
    set.

Derived paths:
  - secret_key_path: always ``{work_dir}/secret_key``.
  - jobs_dir: ``{work_dir}/jobs`` unless explicitly set in [jobs].

SLO upload threshold:
  - swift_slo_segment_size_bytes: threshold above which Swift Static Large
    Object (SLO) is used. The same value is also the size of each segment.
    Default 4 GiB; configurable in the [swift] section as
    ``slo_segment_size_bytes``.

Async job manager directory:
  - jobs_dir: directory where the JobManager persists one JSON file per
    async acquisition job. Defaults to ``{work_dir}/jobs``; the [jobs]
    section is optional and only needed to override the default location.
"""
from __future__ import annotations

import configparser
import os
from dataclasses import dataclass
from typing import Optional

DEFAULT_CONFIG_PATH = "/etc/forensicnova/forensicnova.conf"
DEFAULT_WORK_DIR = "/var/lib/forensicnova"
DEFAULT_SLO_SEGMENT_SIZE_BYTES = 4 * 1024 ** 3  # 4 GiB


@dataclass
class Config:
    """Typed view of forensicnova.conf."""

    # [DEFAULT] — runtime / bind
    bind_host: str = "0.0.0.0"
    bind_port: int = 5234
    work_dir: str = DEFAULT_WORK_DIR
    log_dir: str = "/var/log/forensicnova"

    # [keystone] — identity discovery
    keystone_auth_url: str = ""
    keystone_region: str = "RegionOne"
    keystone_forensic_role: str = "forensic_analyst"

    # [keystone_authtoken] — service credentials for keystonemiddleware
    keystone_authtoken_username: str = "admin"
    keystone_authtoken_password: str = ""
    keystone_authtoken_project:  str = "admin"

    # [swift] — object storage
    swift_container: str = "forensics"
    # Files >= this size go through SLO. The same value sizes each segment.
    swift_slo_segment_size_bytes: int = DEFAULT_SLO_SEGMENT_SIZE_BYTES

    # [forensics] — DFIR project context
    forensics_project: str = "forensics"
    forensics_dfir_user: str = "dfir-tester"

    # [libvirt] — hypervisor connection
    libvirt_uri: str = "qemu:///system"

    # [jobs] — async job manager.
    # Empty by default; load_config() derives it from work_dir when unset.
    jobs_dir: str = ""

    # Flask — session signing key path (derived from work_dir in load_config)
    secret_key_path: str = f"{DEFAULT_WORK_DIR}/secret_key"

    # Bookkeeping
    config_path: str = DEFAULT_CONFIG_PATH


def load_config(path: Optional[str] = None) -> Config:
    """Load ForensicNova config from an INI file."""
    cfg_path = path or os.environ.get("FORENSICNOVA_CONFIG", DEFAULT_CONFIG_PATH)

    cp = configparser.ConfigParser()
    cp.optionxform = str  # preserve key case
    read_files = cp.read(cfg_path)

    cfg = Config(config_path=cfg_path)

    if read_files:
        cfg.bind_host = cp.get("DEFAULT", "bind_host", fallback=cfg.bind_host)
        cfg.bind_port = cp.getint("DEFAULT", "bind_port", fallback=cfg.bind_port)
        cfg.work_dir  = cp.get("DEFAULT", "work_dir",  fallback=cfg.work_dir)
        cfg.log_dir   = cp.get("DEFAULT", "log_dir",   fallback=cfg.log_dir)

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

    if cp.has_section("keystone_authtoken"):
        cfg.keystone_authtoken_username = cp.get(
            "keystone_authtoken", "username",
            fallback=cfg.keystone_authtoken_username,
        )
        cfg.keystone_authtoken_password = cp.get(
            "keystone_authtoken", "password",
            fallback=cfg.keystone_authtoken_password,
        )
        cfg.keystone_authtoken_project = cp.get(
            "keystone_authtoken", "project_name",
            fallback=cfg.keystone_authtoken_project,
        )

    env_pwd = os.environ.get("FORENSICNOVA_KEYSTONE_AUTHTOKEN_PASSWORD", "")
    if env_pwd:
        cfg.keystone_authtoken_password = env_pwd

    if cp.has_section("swift"):
        cfg.swift_container = cp.get(
            "swift", "container", fallback=cfg.swift_container
        )
        cfg.swift_slo_segment_size_bytes = cp.getint(
            "swift", "slo_segment_size_bytes",
            fallback=cfg.swift_slo_segment_size_bytes,
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

    # [jobs] is optional: only present to override the default location.
    if cp.has_section("jobs"):
        cfg.jobs_dir = cp.get("jobs", "jobs_dir", fallback=cfg.jobs_dir)

    cfg.secret_key_path = os.path.join(cfg.work_dir, "secret_key")

    # Derive jobs_dir from work_dir when it was not explicitly configured.
    if not cfg.jobs_dir:
        cfg.jobs_dir = os.path.join(cfg.work_dir, "jobs")

    return cfg
