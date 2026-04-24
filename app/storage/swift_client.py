"""ForensicNova — Swift object storage client with forensic integrity checks.

Uses python-swiftclient in the two-step pattern:
  1. Authenticate against Keystone via swiftclient.client.get_auth() to obtain
     a (storage_url, auth_token) tuple.
  2. Upload/list/download artifacts with swiftclient.client.*(url=..., token=...).

This is the official pattern from the python-swiftclient docs; the earlier
attempt of passing authurl/user/key directly to put_object() was wrong and
failed with 'unexpected keyword argument'.

Forensic integrity check (end-to-end):
  Swift independently computes MD5 of the received bytes and returns it as
  the ETag header in the PUT response.  We compare it against the MD5 we
  computed locally with hasher.py.  Match  -> "swift_upload_verified"
  (caller may secure_delete).  Mismatch -> "swift_upload_integrity_failure"
  (local file preserved, IntegrityError raised).

Credentials:
  - Auth URL, username, project, region: from the ForensicNova Config.
  - Password: from environment variable FORENSICNOVA_DFIR_PASSWORD
    (injected by the systemd unit's Environment= directive written by
    devstack/plugin.sh).

Upload strategy:
  - Files < SIMPLE_UPLOAD_THRESHOLD (4 GB): single PUT, ETag = MD5(content).
  - Files >= threshold: Swift Large Object (SLO) — deferred to thesis.

Read operations:
  - list_reports()          : enumerate report-*.json in forensics container.
  - download_json()          : fetch a small JSON object as bytes (full load).
  - stream_object()          : yield chunks from a Swift object (any size).
                               Used for large dumps — never loads the whole
                               file into memory on the Flask side.
  No CoC events are emitted on read operations — the chain of custody is
  concerned with evidence genesis, not post-hoc consultation.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Callable, Iterator, Optional, Tuple

import swiftclient
import swiftclient.exceptions

log = logging.getLogger("forensicnova.storage")

SIMPLE_UPLOAD_THRESHOLD = 4 * 1024 ** 3  # 4 GB
_PASSWORD_ENV = "FORENSICNOVA_DFIR_PASSWORD"

# Prefix used for JSON report objects in Swift — must stay in sync with the
# naming convention enforced by app/api/v1.py:memory_acquire().
REPORT_OBJECT_PREFIX = "report-"

# Download chunk size — 1 MB is a sweet spot for HTTP streaming:
# small enough that the first byte reaches the client quickly, large
# enough that syscalls overhead is negligible for multi-GB dumps.
_STREAM_CHUNK_SIZE = 1024 * 1024


class IntegrityError(RuntimeError):
    """Raised when Swift ETag does not match the locally computed MD5.

    The caller must NOT invoke secure_delete() when this is raised —
    the local dump file must be preserved for forensic debugging.
    """


class SwiftObjectNotFound(RuntimeError):
    """Raised when a requested Swift object does not exist in the container."""


# ---------------------------------------------------------------------------
# Public API — writes
# ---------------------------------------------------------------------------

def upload_dump(
    local_path: Path,
    object_name: str,
    metadata: dict,
    cfg,
    password: Optional[str] = None,
    log_event: Optional[Callable[[str, dict], None]] = None,
) -> dict:
    """Upload a forensic artifact to Swift with integrity verification."""
    local_path = Path(local_path)
    password = _resolve_password(password)
    container = cfg.swift_container

    file_size = local_path.stat().st_size
    log.info(
        "upload starting: %s -> swift://%s/%s (%.1f MB)",
        local_path, container, object_name, file_size / 1024 / 1024,
    )
    _emit(log_event, "swift_upload_started", {
        "object_name": object_name,
        "container": container,
        "size_bytes": file_size,
    })

    if file_size >= SIMPLE_UPLOAD_THRESHOLD:
        raise NotImplementedError(
            f"File size {file_size // 1024 // 1024} MB exceeds the "
            f"{SIMPLE_UPLOAD_THRESHOLD // 1024 // 1024} MB simple-upload "
            "threshold.  SLO support is planned for the thesis milestone."
        )

    url, token = _authenticate(cfg, password)
    _ensure_container(url, token, container)

    headers = {f"X-Object-Meta-{k}": str(v) for k, v in metadata.items()}
    expected_md5 = metadata.get("md5", "")

    with local_path.open("rb") as fh:
        swift_etag = swiftclient.client.put_object(
            url=url,
            token=token,
            container=container,
            name=object_name,
            contents=fh,
            content_length=file_size,
            headers=headers,
        )

    log.info(
        "swift PUT completed: object=%s/%s, etag=%s",
        container, object_name, swift_etag,
    )

    etag_verified = _verify_etag(
        swift_etag, expected_md5, object_name, container, file_size, log_event,
    )

    if etag_verified is False and expected_md5:
        raise IntegrityError(f"ETag verification failed for {object_name}")

    return {
        "swift_object":  f"{container}/{object_name}",
        "swift_etag":    (swift_etag or "").strip('"'),
        "etag_verified": bool(etag_verified),
        "size_bytes":    file_size,
    }


def upload_json(
    json_bytes: bytes,
    object_name: str,
    cfg,
    password: Optional[str] = None,
    log_event: Optional[Callable[[str, dict], None]] = None,
) -> dict:
    """Upload a JSON report (bytes) to Swift."""
    password = _resolve_password(password)
    container = cfg.swift_container

    url, token = _authenticate(cfg, password)
    _ensure_container(url, token, container)

    log.info(
        "uploading JSON report: %s/%s (%d bytes)",
        container, object_name, len(json_bytes),
    )

    swift_etag = swiftclient.client.put_object(
        url=url,
        token=token,
        container=container,
        name=object_name,
        contents=json_bytes,
        content_type="application/json",
    )

    _emit(log_event, "swift_report_uploaded", {
        "object_name": object_name,
        "container":   container,
        "size_bytes":  len(json_bytes),
    })

    return {
        "swift_object": f"{container}/{object_name}",
        "swift_etag":   (swift_etag or "").strip('"'),
        "size_bytes":   len(json_bytes),
    }


# ---------------------------------------------------------------------------
# Public API — reads
# ---------------------------------------------------------------------------

def list_reports(
    cfg,
    password: Optional[str] = None,
) -> list[str]:
    """Enumerate JSON report objects in the forensics container."""
    password = _resolve_password(password)
    container = cfg.swift_container

    url, token = _authenticate(cfg, password)

    log.debug("listing container %s with prefix=%r", container, REPORT_OBJECT_PREFIX)

    try:
        _headers, objects = swiftclient.client.get_container(
            url=url,
            token=token,
            container=container,
            prefix=REPORT_OBJECT_PREFIX,
            full_listing=True,
        )
    except swiftclient.exceptions.ClientException as exc:
        if getattr(exc, "http_status", None) == 404:
            log.warning("container %s does not exist yet", container)
            return []
        raise

    names = [
        obj["name"]
        for obj in objects
        if obj.get("name", "").endswith(".json")
    ]
    log.info("list_reports: found %d report objects in %s", len(names), container)
    return sorted(names)


def download_json(
    object_name: str,
    cfg,
    password: Optional[str] = None,
) -> bytes:
    """Download a single JSON object from Swift as raw bytes (full load).

    For small objects only.  Do NOT use on dump-*.raw files — use
    stream_object() instead to avoid loading hundreds of MB into RAM.
    """
    password = _resolve_password(password)
    container = cfg.swift_container

    url, token = _authenticate(cfg, password)

    log.debug("downloading swift://%s/%s", container, object_name)

    try:
        _headers, content = swiftclient.client.get_object(
            url=url,
            token=token,
            container=container,
            name=object_name,
        )
    except swiftclient.exceptions.ClientException as exc:
        if getattr(exc, "http_status", None) == 404:
            raise SwiftObjectNotFound(
                f"object not found: {container}/{object_name}"
            ) from exc
        raise

    size = len(content) if isinstance(content, (bytes, bytearray)) else -1
    log.debug("downloaded %s (%d bytes)", object_name, size)
    return content


def stream_object(
    object_name: str,
    cfg,
    password: Optional[str] = None,
    chunk_size: int = _STREAM_CHUNK_SIZE,
) -> Tuple[dict, Iterator[bytes]]:
    """Stream a Swift object in chunks without loading it all into RAM.

    Used for large forensic dumps that can exceed available RAM.
    swiftclient.client.get_object() with resp_chunk_size returns a generator
    that fetches the object in chunks directly from the Swift server.

    :returns: (headers dict, chunk iterator).  Caller is responsible for
              forwarding the chunks (e.g. Flask Response(stream_with_context)).
    :raises SwiftObjectNotFound: if the object is not in the container.
    """
    password = _resolve_password(password)
    container = cfg.swift_container

    url, token = _authenticate(cfg, password)

    log.info("stream starting: swift://%s/%s (chunk=%d)",
             container, object_name, chunk_size)

    try:
        headers, body_iter = swiftclient.client.get_object(
            url=url,
            token=token,
            container=container,
            name=object_name,
            resp_chunk_size=chunk_size,
        )
    except swiftclient.exceptions.ClientException as exc:
        if getattr(exc, "http_status", None) == 404:
            raise SwiftObjectNotFound(
                f"object not found: {container}/{object_name}"
            ) from exc
        raise

    return headers, body_iter


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _authenticate(cfg, password: str) -> Tuple[str, str]:
    """Authenticate to Keystone v3 and return (storage_url, token)."""
    os_options = {
        "project_name":      cfg.forensics_project,
        "user_domain_id":    "default",
        "project_domain_id": "default",
        "region_name":       cfg.keystone_region,
    }

    log.debug(
        "authenticating to keystone: url=%s user=%s project=%s",
        cfg.keystone_auth_url, cfg.forensics_dfir_user, cfg.forensics_project,
    )

    storage_url, token = swiftclient.client.get_auth(
        auth_url=cfg.keystone_auth_url,
        user=cfg.forensics_dfir_user,
        key=password,
        auth_version="3",
        os_options=os_options,
    )
    log.info("keystone auth OK, storage_url=%s", storage_url)
    return storage_url, token


def _ensure_container(url: str, token: str, container: str) -> None:
    """PUT the container idempotently."""
    try:
        swiftclient.client.put_container(url=url, token=token, container=container)
        log.debug("container ensured: %s", container)
    except swiftclient.exceptions.ClientException as exc:
        if getattr(exc, "http_status", None) in (202, 204):
            log.debug("container already exists: %s", container)
            return
        raise


def _verify_etag(
    swift_etag: Optional[str],
    expected_md5: str,
    object_name: str,
    container: str,
    file_size: int,
    log_event: Optional[Callable[[str, dict], None]],
) -> bool:
    if not expected_md5 or not swift_etag:
        log.warning(
            "etag verification skipped: expected_md5=%r swift_etag=%r",
            expected_md5, swift_etag,
        )
        return False

    etag_clean = swift_etag.strip('"')
    if etag_clean.lower() == expected_md5.lower():
        log.info("etag verification OK: %s", etag_clean)
        _emit(log_event, "swift_upload_verified", {
            "object_name": object_name,
            "container": container,
            "etag": etag_clean,
            "md5": expected_md5,
            "size_bytes": file_size,
        })
        return True

    log.error(
        "INTEGRITY FAILURE: swift etag=%s != local md5=%s — "
        "local file preserved, do NOT invoke secure_delete",
        etag_clean, expected_md5,
    )
    _emit(log_event, "swift_upload_integrity_failure", {
        "object_name": object_name,
        "container": container,
        "swift_etag": etag_clean,
        "local_md5": expected_md5,
        "size_bytes": file_size,
    })
    raise IntegrityError(
        f"ETag mismatch for {object_name}: "
        f"swift={etag_clean} local_md5={expected_md5}. "
        "Local dump preserved. Investigate before proceeding."
    )


def _resolve_password(password: Optional[str]) -> str:
    if password:
        return password
    pwd = os.environ.get(_PASSWORD_ENV, "")
    if not pwd:
        raise EnvironmentError(
            f"dfir-tester password not found. "
            f"Set {_PASSWORD_ENV} environment variable or pass password= argument."
        )
    return pwd


def _emit(
    log_event: Optional[Callable[[str, dict], None]],
    event_type: str,
    data: dict,
) -> None:
    log.debug("coc_event %s: %s", event_type, data)
    if log_event is not None:
        log_event(event_type, data)
