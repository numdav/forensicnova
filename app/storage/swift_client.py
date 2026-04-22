"""ForensicNova — Swift object storage client with forensic integrity checks.

Responsibilities:
  1. Authenticate against Keystone as dfir-tester using python-swiftclient.
  2. Upload a raw memory dump (and later the JSON report) to the 'forensics'
     Swift container.
  3. Verify end-to-end integrity via Swift's ETag header:
       Swift independently computes MD5 of the received bytes and returns it
       as the ETag in the PUT response.  We compare it against the MD5 we
       computed locally (from hasher.py) before uploading.
       Match  → chain-of-custody event "swift_upload_verified" → caller may
                 invoke secure_delete().
       Mismatch → chain-of-custody event "swift_upload_integrity_failure"
                  → local file is preserved for forensic debugging
                  → IntegrityError raised to alert the operator.
  4. Attach chain-of-custody metadata to every Swift object as
     X-Object-Meta-* headers, so the evidence is self-describing even
     if the JSON report is lost.

Credentials:
  - Auth URL, username, project, region come from the ForensicNova Config.
  - Password is NOT stored in the config file (it is sensitive).
    It is read from the environment variable FORENSICNOVA_DFIR_PASSWORD,
    which is injected by the systemd unit via the Environment= directive
    written by plugin.sh.

Simple vs SLO upload:
  - Files < SIMPLE_UPLOAD_THRESHOLD (4 GB): single PUT, ETag = MD5(content).
  - Files >= threshold: Swift Large Object (SLO), ETag = MD5 of segment ETags.
    In this case we cannot compare ETag against our full-file MD5 directly;
    instead we verify each segment's ETag individually and store the full-file
    MD5 in object metadata for the SIFT workstation to verify post-download.
    SLO support is scaffolded here but full implementation is deferred to the
    thesis (guest RAM > 5 GB scenario).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Callable, Optional

import swiftclient
import swiftclient.exceptions

log = logging.getLogger("forensicnova.storage")

# Files below this threshold use a simple PUT (ETag = full-file MD5).
SIMPLE_UPLOAD_THRESHOLD = 4 * 1024 ** 3  # 4 GB

# Environment variable that carries the dfir-tester password.
_PASSWORD_ENV = "FORENSICNOVA_DFIR_PASSWORD"


class IntegrityError(RuntimeError):
    """Raised when Swift ETag does not match the locally computed MD5.

    The caller must NOT invoke secure_delete() when this is raised —
    the local dump file must be preserved for forensic debugging.
    """


def upload_dump(
    local_path: Path,
    object_name: str,
    metadata: dict,
    cfg,
    password: Optional[str] = None,
    log_event: Optional[Callable[[str, dict], None]] = None,
) -> dict:
    """Upload a forensic artifact to Swift with integrity verification.

    :param local_path:   Path to the local file to upload (dump or report).
    :param object_name:  Swift object name, e.g. "dump-<uuid>.raw".
    :param metadata:     Chain-of-custody fields to attach as X-Object-Meta-*.
                         Keys must be plain strings (no X-Object-Meta- prefix).
    :param cfg:          ForensicNova Config instance (from app/config.py).
    :param password:     dfir-tester password.  If None, read from env var
                         FORENSICNOVA_DFIR_PASSWORD.
    :param log_event:    Optional CoC callback(event_type, data).

    :returns: dict with:
        - swift_object   (str)  — "<container>/<object_name>"
        - swift_etag     (str)  — ETag returned by Swift
        - etag_verified  (bool) — True if ETag matched local MD5
        - size_bytes     (int)  — bytes uploaded

    :raises IntegrityError:       ETag mismatch (do NOT secure_delete).
    :raises swiftclient.ClientException: Swift/Keystone communication error.
    :raises EnvironmentError:     password missing from env and argument.
    """
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

    os_options = {
        "project_name":      cfg.forensics_project,
        "user_domain_id":    "default",
        "project_domain_id": "default",
        "region_name":       cfg.keystone_region,
    }

    headers = {
        f"X-Object-Meta-{k}": str(v) for k, v in metadata.items()
    }

    expected_md5 = metadata.get("md5", "")

    with local_path.open("rb") as fh:
        swift_etag = swiftclient.client.put_object(
            authurl=cfg.keystone_auth_url,
            user=cfg.forensics_dfir_user,
            key=password,
            container=container,
            name=object_name,
            contents=fh,
            content_length=file_size,
            auth_version="3",
            os_options=os_options,
            headers=headers,
        )

    log.info(
        "swift PUT completed: object=%s/%s, etag=%s",
        container, object_name, swift_etag,
    )

    if expected_md5 and swift_etag:
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
            etag_verified = True
        else:
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
    else:
        log.warning(
            "etag verification skipped: expected_md5=%r swift_etag=%r",
            expected_md5, swift_etag,
        )
        etag_verified = False

    return {
        "swift_object":  f"{container}/{object_name}",
        "swift_etag":    swift_etag.strip('"'),
        "etag_verified": etag_verified,
        "size_bytes":    file_size,
    }


def upload_json(
    json_bytes: bytes,
    object_name: str,
    cfg,
    password: Optional[str] = None,
    log_event: Optional[Callable[[str, dict], None]] = None,
) -> dict:
    """Upload a JSON report (bytes) to Swift.

    No etag verification needed: the report is generated by us,
    not an evidence artifact.

    :returns: dict with swift_object, swift_etag, size_bytes.
    """
    password = _resolve_password(password)
    container = cfg.swift_container

    os_options = {
        "project_name":      cfg.forensics_project,
        "user_domain_id":    "default",
        "project_domain_id": "default",
        "region_name":       cfg.keystone_region,
    }

    log.info("uploading JSON report: %s/%s (%d bytes)",
             container, object_name, len(json_bytes))

    swift_etag = swiftclient.client.put_object(
        authurl=cfg.keystone_auth_url,
        user=cfg.forensics_dfir_user,
        key=password,
        container=container,
        name=object_name,
        contents=json_bytes,
        content_type="application/json",
        auth_version="3",
        os_options=os_options,
    )

    _emit(log_event, "swift_report_uploaded", {
        "object_name": object_name,
        "container":   container,
        "size_bytes":  len(json_bytes),
    })

    return {
        "swift_object": f"{container}/{object_name}",
        "swift_etag":   swift_etag.strip('"'),
        "size_bytes":   len(json_bytes),
    }


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _resolve_password(password: Optional[str]) -> str:
    """Return password from argument or environment variable."""
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
