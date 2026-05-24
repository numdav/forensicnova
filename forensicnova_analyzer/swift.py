"""ForensicNova Analyzer — Swift object storage client.

Read/write companion to `app/storage/swift_client.py` (acquisition
backend), scoped to the analyzer's needs:

  - Authenticate against Keystone as the dfir-tester service account
    (same two-step pattern as the acquisition backend).
  - Stream a dump object to a local working directory while computing
    MD5+SHA1 in a single pass.
  - List/find acquisition reports already stored in Swift.
  - Upload an analysis result JSON to Swift with custom metadata.

Architectural choices:

  Why duplicate (and not import from app/storage/swift_client.py):
    The two backends are independently deployed services with separate
    venvs and lifecycles. A shared library would couple them in ways
    that complicate deploy and reasoning. The duplication is scoped:
    the acquisition swift_client.py implements upload-with-ETag and
    SLO upload logic that the analyzer does NOT need. The analyzer
    only needs read paths plus a small-object JSON upload, so the
    duplicated code surface stays minimal (~250 lines vs ~900).

  Why service-account auth (not the API caller's token):
    Authorization is separated from execution. Keystonemiddleware in
    the HTTP layer (activated in Stage E2+) validates the caller has
    the `forensic_analyst` role on the forensics project. The backend
    then acts with its own dfir-tester identity when talking to Swift.
    Every Swift operation is logged under the service account, while
    the human operator is tracked at application level via job records
    and (future) CoC events. This is the same pattern used by the
    acquisition backend.

  Why single-pass MD5+SHA1 during streaming download:
    A dump can be 4-32 GiB; doing two passes (one to write to disk,
    one to re-hash) would double the I/O cost. The streaming reader
    updates both hashers as each chunk arrives, writes the chunk to
    disk, and advances. RAM stays constant at the chunk size (1 MiB).

  Credentials:
    The dfir-tester password is read from env var
    FORENSICNOVA_DFIR_PASSWORD at call time. The systemd unit injects
    it via an Environment= directive populated from the DevStack
    plugin's local.conf variable. The password never lives in the
    on-disk INI config of the analyzer.

  Naming convention (must stay in sync with app/jobs/runner.py):
    dump:    dump-<vm_name_safe>-<timestamp_compact>.raw
    report:  report-<vm_name_safe>-<timestamp_compact>.json
    analysis: analysis-<analyzer>-<acquisition_id>-<UTC>.json
             (produced by upload_analysis_json; the caller is
              responsible for building the object_name string)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Callable, Optional, Tuple

import swiftclient
import swiftclient.exceptions

log = logging.getLogger("forensicnova_analyzer.swift")

# Prefix used for JSON report objects in Swift — must stay in sync with
# the naming convention enforced by app/jobs/runner.py.
REPORT_OBJECT_PREFIX = "report-"

# Acquisition report schema versions this analyzer can navigate. The
# field layout (e.g. report["dump"]["md5"] vs report["md5"]) depends on
# the version: summarize_acquisition() raises UnsupportedReportSchema
# when it encounters a value not in this set. Extend by adding a string
# (e.g. "1.3") once the navigation paths in summarize_acquisition() have
# been updated to handle it.
SUPPORTED_REPORT_SCHEMA_VERSIONS = frozenset({"1.2"})

# Streaming chunk size for download_dump_with_hashes(). 1 MiB is the
# sweet spot for HTTP streaming + hashing: large enough to amortise
# per-syscall overhead, small enough to keep RAM constant.
_DOWNLOAD_CHUNK_SIZE = 1024 * 1024  # 1 MiB

# Env var name used to inject the dfir-tester password into the service
# (set by the DevStack plugin in the systemd unit). Same convention as
# app/storage/swift_client.py.
_PASSWORD_ENV = "FORENSICNOVA_DFIR_PASSWORD"

# Progress callback fires every N chunks during download_dump_with_hashes.
# 1024 chunks * 1 MiB = ~1 GiB between progress updates — fine-grained
# enough for a 4-32 GiB dump without spamming the job record.
_PROGRESS_EVERY_N_CHUNKS = 1024


class SwiftObjectNotFound(RuntimeError):
    """Raised when a requested Swift object does not exist (HTTP 404)."""


class IntegrityError(RuntimeError):
    """Raised when downloaded bytes fail the post-download hash check.

    Carries the expected and computed hashes so the caller can decide
    whether to log them as evidence in a CoC event.
    """


class UnsupportedReportSchema(RuntimeError):
    """Raised when an acquisition report's schema_version is not in
    SUPPORTED_REPORT_SCHEMA_VERSIONS.

    This is a fail-fast guard for chain of custody: if the analyzer
    cannot reliably extract md5/sha1/instance from a report, it must
    refuse to drive an analysis on top of it rather than silently
    skipping the coherence check.
    """


def download_dump_with_hashes(
    object_name: str,
    dest_path: Path,
    cfg,
    password: Optional[str] = None,
    chunk_size: int = _DOWNLOAD_CHUNK_SIZE,
    progress_callback: Optional[Callable[[str], None]] = None,
) -> dict:
    """Stream a Swift object to disk while computing MD5+SHA1 single-pass.

    For SLO objects, Swift transparently re-assembles the segments at
    GET time, so the caller sees a continuous byte stream regardless of
    upload method (single PUT or SLO).

    :param object_name:       Swift object name (e.g. "dump-vm01-20260523T100000Z.raw")
    :param dest_path:         absolute path on local disk where the file will be written
    :param cfg:               AnalyzerConfig instance
    :param password:          optional override; if None, read from env var
    :param chunk_size:        HTTP read chunk size in bytes (default 1 MiB)
    :param progress_callback: optional callable(label: str), invoked every
                              ~1 GiB during download. Best-effort:
                              exceptions raised inside it are swallowed.

    :returns: dict with keys:
        - size_bytes  (int) : total bytes written
        - md5         (str) : hex MD5 of received bytes
        - sha1        (str) : hex SHA1 of received bytes
        - chunk_count (int) : number of HTTP chunks consumed

    :raises SwiftObjectNotFound: if the object does not exist (404)
    :raises swiftclient.exceptions.ClientException: on other Swift errors
    """
    password = _resolve_password(password)
    container = cfg.swift_container
    url, token = _authenticate(cfg, password)

    log.info("download starting: swift://%s/%s -> %s",
             container, object_name, dest_path)

    try:
        _headers, body_iter = swiftclient.client.get_object(
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

    dest_path = Path(dest_path)
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    md5_hasher = hashlib.md5()
    sha1_hasher = hashlib.sha1()
    size_bytes = 0
    chunk_count = 0

    # Single-pass hashing + write: each chunk feeds both hashers and
    # then hits disk. The full file never lives in RAM.
    with dest_path.open("wb") as fh:
        for chunk in body_iter:
            md5_hasher.update(chunk)
            sha1_hasher.update(chunk)
            fh.write(chunk)
            size_bytes += len(chunk)
            chunk_count += 1
            if (
                progress_callback is not None
                and chunk_count % _PROGRESS_EVERY_N_CHUNKS == 0
            ):
                try:
                    gib = size_bytes / (1024 ** 3)
                    progress_callback(
                        f"Downloading dump ({gib:.1f} GiB streamed)"
                    )
                except Exception:  # noqa: BLE001 — best-effort by design
                    pass
        fh.flush()
        os.fsync(fh.fileno())

    md5_hex = md5_hasher.hexdigest()
    sha1_hex = sha1_hasher.hexdigest()

    log.info(
        "download complete: %s (%d bytes, md5=%s, sha1=%s, %d chunks)",
        object_name, size_bytes, md5_hex, sha1_hex, chunk_count,
    )

    return {
        "size_bytes":  size_bytes,
        "md5":         md5_hex,
        "sha1":        sha1_hex,
        "chunk_count": chunk_count,
    }


def list_acquisitions(
    cfg,
    password: Optional[str] = None,
) -> list[dict]:
    """List all acquisition reports stored in the forensics container.

    For each `report-*.json` object found, fetches and parses the JSON
    payload. Returns the list of parsed report dicts. Order is whatever
    Swift's container listing yields (typically alphabetical, which by
    construction sorts by VM name then timestamp).

    Reports are small (~10 KB each), so this is cheap up to a few
    hundreds; for thousands of acquisitions a paginated/indexed design
    would be needed but is out of scope.
    """
    password = _resolve_password(password)
    container = cfg.swift_container
    url, token = _authenticate(cfg, password)

    log.debug(
        "listing acquisitions in container '%s' (prefix '%s')",
        container, REPORT_OBJECT_PREFIX,
    )

    try:
        _headers, objects = swiftclient.client.get_container(
            url=url,
            token=token,
            container=container,
            prefix=REPORT_OBJECT_PREFIX,
        )
    except swiftclient.exceptions.ClientException as exc:
        if getattr(exc, "http_status", None) == 404:
            # Container itself missing — treat as empty rather than error;
            # this is the post-unstack/stack state before any acquisition.
            log.info("container '%s' not present yet — returning []", container)
            return []
        raise

    acquisitions: list[dict] = []
    for obj_info in objects:
        obj_name = obj_info.get("name")
        if not obj_name:
            continue
        try:
            _h, content = swiftclient.client.get_object(
                url=url,
                token=token,
                container=container,
                name=obj_name,
            )
            report = json.loads(content)
            acquisitions.append(report)
        except (swiftclient.exceptions.ClientException, ValueError) as exc:
            # Skip malformed or unreadable reports — don't fail the whole
            # listing if a single object is corrupted.
            log.warning(
                "could not parse acquisition report '%s': %s",
                obj_name, exc,
            )
            continue

    log.info(
        "listed %d acquisition(s) from container '%s'",
        len(acquisitions), container,
    )
    return acquisitions


def find_acquisition(
    acquisition_id: str,
    cfg,
    password: Optional[str] = None,
) -> Optional[dict]:
    """Look up a single acquisition report by its acquisition_id field.

    Iterates `list_acquisitions()` and matches on the top-level
    `acquisition_id` key of each report. Returns the matching report
    dict, or None if no acquisition with that ID is found.

    The report JSON contains everything needed to drive an analysis:
    the dump's swift object name, MD5 + SHA1 (for the post-download
    coherence check), instance metadata, etc.
    """
    for report in list_acquisitions(cfg, password=password):
        if report.get("acquisition_id") == acquisition_id:
            return report
    return None


def summarize_acquisition(report: dict) -> dict:
    """Flatten an acquisition report into a stable summary dict.

    This is the **single point of truth** for the analyzer's coupling
    with the acquisition report JSON schema. Every other module reads
    summary fields, never the nested report. When the acquisition
    backend bumps the schema (v1.2 -> v1.3), only this function and
    SUPPORTED_REPORT_SCHEMA_VERSIONS need updating.

    Current schema reference (v1.2):
        report["schema_version"]              -> "1.2"
        report["acquisition_id"]              -> top-level UUID
        report["instance"]["name"]            -> Nova instance name
        report["instance"]["id"]              -> Nova instance UUID
        report["dump"]["md5"]                 -> 32-hex MD5 of dump
        report["dump"]["sha1"]                -> 40-hex SHA1 of dump
        report["dump"]["size_bytes"]          -> integer file size
        report["dump"]["swift_object"]        -> "container/object" full path
        report["timestamps"]["completed_at"]  -> ISO8601 UTC

    :returns: dict with the following keys (all string except where noted):
        - schema_version
        - acquisition_id
        - instance_name
        - instance_id
        - dump_object_name   (str): just the object name, no container
        - dump_swift_object  (str): "container/object" full path
        - dump_md5
        - dump_sha1
        - dump_size_bytes    (int)
        - completed_at

    :raises UnsupportedReportSchema: if report["schema_version"] is not
        in SUPPORTED_REPORT_SCHEMA_VERSIONS.
    :raises KeyError: if a mandatory field is missing inside an
        otherwise-supported schema version (report is malformed).
    """
    if not isinstance(report, dict):
        raise UnsupportedReportSchema(
            f"report is not a dict: got {type(report).__name__}"
        )

    schema_version = str(report.get("schema_version", "")).strip()
    if schema_version not in SUPPORTED_REPORT_SCHEMA_VERSIONS:
        raise UnsupportedReportSchema(
            f"unsupported acquisition report schema_version={schema_version!r}; "
            f"supported: {sorted(SUPPORTED_REPORT_SCHEMA_VERSIONS)}"
        )

    # v1.2 navigation. KeyError here means the report claims v1.2 but
    # is structurally malformed — that is an upstream bug, not a
    # version-skew problem, so we let KeyError propagate untouched.
    instance = report["instance"]
    dump = report["dump"]
    timestamps = report.get("timestamps", {})

    # target_system block (added in v1.2): Nova/Glance/libvirt metadata
    # collected at acquisition time. Glance os_type / os_distro feed
    # the analyzer's OS hint resolver — both may be None when the
    # original Glance image carries no os_* properties (lesson from
    # the F1/F2 era: many private images lack these annotations).
    target_system = report.get("target_system") or {}
    glance = target_system.get("glance") or {}
    glance_os_type = glance.get("os_type")
    glance_os_distro = glance.get("os_distro")

    swift_obj_full = dump["swift_object"]  # e.g. "forensics/dump-vm01-...raw"
    # Split off the container prefix to obtain the bare object name
    # (the form expected by swiftclient.client.get_object).
    if "/" in swift_obj_full:
        dump_object_name = swift_obj_full.split("/", 1)[1]
    else:
        dump_object_name = swift_obj_full

    return {
        "schema_version":   schema_version,
        "acquisition_id":   report["acquisition_id"],
        "instance_name":    instance["name"],
        "instance_id":      instance["id"],
        "dump_object_name": dump_object_name,
        "dump_swift_object": swift_obj_full,
        "dump_md5":         dump["md5"],
        "dump_sha1":        dump["sha1"],
        "dump_size_bytes":  int(dump["size_bytes"]),
        "completed_at":     timestamps.get("completed_at", ""),
        # Glance hints (may be None) — used by analyzers/volatility
        # ._resolve_os to pick the right plugin namespace. Passed
        # through raw; the analyzer owns the normalisation policy.
        "glance_os_type":   glance_os_type,
        "glance_os_distro": glance_os_distro,
    }


def upload_analysis_json(
    json_bytes: bytes,
    object_name: str,
    metadata: dict,
    cfg,
    password: Optional[str] = None,
) -> dict:
    """Upload an analysis result JSON to Swift with custom metadata.

    The metadata dict is translated to Swift X-Object-Meta-* headers
    (one header per dict entry), the standard way to attach searchable
    annotations to a Swift object. Same convention used by the
    acquisition backend for dumps.

    :param json_bytes:   already-serialized JSON payload
    :param object_name:  Swift object name, e.g.
                         "analysis-volatility-fast-<acq_id>-<UTC>.json"
    :param metadata:     dict whose entries become X-Object-Meta-* headers
    :param cfg:          AnalyzerConfig instance
    :param password:     optional override; if None, read from env var

    :returns: dict with keys:
        - swift_object (str): "container/object" path
        - swift_etag   (str): ETag returned by Swift (MD5 of the body)
        - size_bytes   (int): payload size
    """
    password = _resolve_password(password)
    container = cfg.swift_container
    url, token = _authenticate(cfg, password)

    headers = {f"X-Object-Meta-{k}": str(v) for k, v in metadata.items()}

    log.info(
        "uploading analysis: swift://%s/%s (%d bytes)",
        container, object_name, len(json_bytes),
    )

    try:
        etag = swiftclient.client.put_object(
            url=url,
            token=token,
            container=container,
            name=object_name,
            contents=json_bytes,
            content_type="application/json",
            headers=headers,
        )
    except swiftclient.exceptions.ClientException as exc:
        log.error("upload failed: %s", exc)
        raise

    log.info(
        "analysis uploaded: swift://%s/%s (etag=%s, %d bytes)",
        container, object_name, etag, len(json_bytes),
    )

    return {
        "swift_object": f"{container}/{object_name}",
        "swift_etag":   etag,
        "size_bytes":   len(json_bytes),
    }


def verify_dump_hashes(
    computed_md5: str,
    computed_sha1: str,
    expected_md5: str,
    expected_sha1: str,
) -> None:
    """Compare hashes computed from a downloaded dump against the
    expected ones declared in the acquisition report.

    Both pairs are passed as plain hex strings so this function is
    independent of the report's JSON schema. The caller is expected to
    have already navigated the report (e.g. via summarize_acquisition)
    and produced the four hex strings.

    All values are lower-cased before comparison so a mixed-case input
    (e.g. uppercase hex from a third-party tool) does not produce a
    false mismatch.

    :raises IntegrityError: if either hash mismatches, or if any of the
        four arguments is empty (means the caller lost information
        upstream and should not pretend the check succeeded).

    The caller is responsible for emitting any CoC event before/after
    this call.
    """
    cm = (computed_md5 or "").lower()
    cs = (computed_sha1 or "").lower()
    em = (expected_md5 or "").lower()
    es = (expected_sha1 or "").lower()

    if not (cm and cs and em and es):
        raise IntegrityError(
            "incomplete hash inputs for coherence check — "
            f"computed_md5='{cm}' computed_sha1='{cs}' "
            f"expected_md5='{em}' expected_sha1='{es}'"
        )

    md5_ok = cm == em
    sha1_ok = cs == es

    if md5_ok and sha1_ok:
        log.info(
            "hash coherence check passed (md5=%s, sha1=%s)",
            cm, cs,
        )
        return

    raise IntegrityError(
        "hash mismatch after download — "
        f"md5 expected={em} got={cm} (match={md5_ok}); "
        f"sha1 expected={es} got={cs} (match={sha1_ok})"
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _authenticate(cfg, password: str) -> Tuple[str, str]:
    """Two-step Keystone auth: returns (storage_url, auth_token).

    Same pattern as app/storage/swift_client.py: get_auth() once per
    operation. We do NOT cache the token because operations are
    relatively rare (one analysis per minutes-to-hours) and a stale
    token would silently break Swift calls. The cost of a fresh auth
    (~50 ms) is negligible compared to a Volatility scan.
    """
    os_options = {
        "project_name":      cfg.forensics_project,
        "user_domain_id":    "default",
        "project_domain_id": "default",
        "region_name":       cfg.keystone_region,
    }

    log.debug(
        "authenticating to keystone: url=%s user=%s project=%s",
        cfg.keystone_auth_url,
        cfg.forensics_dfir_user,
        cfg.forensics_project,
    )

    storage_url, token = swiftclient.client.get_auth(
        auth_url=cfg.keystone_auth_url,
        user=cfg.forensics_dfir_user,
        key=password,
        auth_version="3",
        os_options=os_options,
    )
    log.debug("keystone auth OK, storage_url=%s", storage_url)
    return storage_url, token


def _resolve_password(password: Optional[str]) -> str:
    """Resolve the dfir-tester password from arg or env var.

    Caller-supplied password (test override) wins over env var. If
    neither is present, raise RuntimeError so the calling code fails
    early rather than producing a confusing 401 from Keystone later.
    """
    if password:
        return password
    env_pwd = os.environ.get(_PASSWORD_ENV, "")
    if not env_pwd:
        raise RuntimeError(
            f"no password provided and {_PASSWORD_ENV} not set "
            "in environment (check systemd unit Environment= directives)"
        )
    return env_pwd
