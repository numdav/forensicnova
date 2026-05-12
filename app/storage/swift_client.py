"""ForensicNova — Swift object storage client with forensic integrity checks.

Uses python-swiftclient in the two-step pattern:
  1. Authenticate against Keystone via swiftclient.client.get_auth() to obtain
     a (storage_url, auth_token) tuple.
  2. Upload/list/download artifacts with swiftclient.client.*(url=..., token=...).

This is the official pattern from the python-swiftclient docs.

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

Upload strategy (Feature 2 - SLO):
  - Files <  SIMPLE_UPLOAD_THRESHOLD (default 4 GiB): single PUT,
    ETag = MD5(content).
  - Files >= SIMPLE_UPLOAD_THRESHOLD                : Swift Static Large
    Object (SLO):
       1. File split into segments of size cfg.swift_slo_segment_size_bytes.
       2. Each segment uploaded to the '_segments' sibling container with
          name '<dump_object_name>/seg-NNNN'. The Swift PUT response carries
          an ETag = MD5 of the segment, computed server-side; we cross-check
          it against the MD5 we computed locally while streaming the bytes
          (single I/O pass via _HashingLimitedReader).
       3. JSON manifest is PUT to the main container with the special
          query string 'multipart-manifest=put'. Swift server-side
          validates that every declared segment exists and that its
          etag/size match, then returns 201 Created with the composite
          ETag in the response header. The manifest carries two custom
          headers, X-Object-Meta-Global-Md5 and X-Object-Meta-Global-Sha1,
          containing the hashes of the full file computed by hasher.py
          BEFORE any transfer. These are the canonical forensic seal.
       4. The composite etag returned by Swift on the manifest PUT is
          'md5(concat(segment_etags))-N'. We recompute it locally and
          compare; mismatch raises IntegrityError after cleaning up.
  - On any failure during SLO upload, every segment already PUT in the
    '_segments' container is deleted before the exception propagates,
    so no orphan segments are left behind.

  Why we do NOT use 'heartbeat=on' on the manifest PUT:
    Swift's 'heartbeat=on' option turns the manifest PUT into a
    chunked-transfer-encoded 202 Accepted response whose body contains
    whitespace heartbeats followed by a final "Response Status: 201" line.
    The python-swiftclient library does not parse this body and only
    reads the Etag header for status 200/201 — with a 202 response the
    return value of put_object() is empty, breaking our composite-etag
    verification. By keeping the PUT synchronous (no heartbeat), Swift
    returns a plain 201 Created with the Etag header, swiftclient parses
    it correctly, and the integrity check works. The downside (the PUT
    can take a few seconds while Swift validates each segment) is
    acceptable for our manifest sizes (max ~10 segments).

Read operations:
  - list_reports()    : enumerate report-*.json in the main container.
  - download_json()    : fetch a small JSON object as bytes (full load).
  - stream_object()    : yield chunks from a Swift object (any size).
                         For SLO objects, Swift transparently re-assembles
                         the segments and the analyst sees a single stream.
  No CoC events are emitted on read operations.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
from pathlib import Path
from typing import Callable, Iterator, Optional, Tuple

import swiftclient
import swiftclient.exceptions

log = logging.getLogger("forensicnova.storage")

# Files at or above this size trigger SLO. Default 4 GiB; overridable via
# the [swift] slo_segment_size_bytes setting in the INI (the threshold and
# the segment size are intentionally one and the same: a file at the
# threshold is exactly one full segment).
DEFAULT_SLO_SEGMENT_SIZE = 4 * 1024 ** 3   # 4 GiB

# Naming convention for the auxiliary container that holds segments.
SEGMENTS_CONTAINER_SUFFIX = "_segments"

_PASSWORD_ENV = "FORENSICNOVA_DFIR_PASSWORD"

# Prefix used for JSON report objects in Swift — must stay in sync with the
# naming convention enforced by app/api/v1.py:memory_acquire().
REPORT_OBJECT_PREFIX = "report-"

# Download chunk size — 1 MB is a sweet spot for HTTP streaming.
_STREAM_CHUNK_SIZE = 1024 * 1024

# Read buffer used while streaming a single segment to swiftclient. 4 MB
# keeps memory low while amortising syscall overhead. python-swiftclient
# will call .read(chunk_size) on the file-like we give it.
_SEGMENT_READ_CHUNK = 4 * 1024 * 1024


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
    """Upload a forensic artifact to Swift with integrity verification.

    Branches between single PUT and SLO based on file size and the
    threshold configured in cfg.swift_slo_segment_size_bytes.

    :returns: dict with keys:
        - swift_object   (str): "container/object" path
        - swift_etag     (str): etag returned by Swift (composite for SLO)
        - etag_verified  (bool): True iff integrity check passed
        - size_bytes     (int): full file size
        - upload_method  (str): "single_put" or "slo"
        - slo_segments   (list[dict]): present iff SLO; one entry per
            segment with keys name/etag/size/md5 (suitable for embedding
            in the JSON report).
    """
    local_path = Path(local_path)
    password = _resolve_password(password)

    file_size = local_path.stat().st_size
    threshold = _slo_threshold(cfg)
    container = cfg.swift_container

    log.info(
        "upload starting: %s -> swift://%s/%s (%.2f GiB, threshold %.2f GiB)",
        local_path, container, object_name,
        file_size / (1024 ** 3), threshold / (1024 ** 3),
    )

    if file_size < threshold:
        return _upload_dump_simple(
            local_path=local_path,
            object_name=object_name,
            metadata=metadata,
            cfg=cfg,
            password=password,
            file_size=file_size,
            log_event=log_event,
        )
    else:
        return _upload_dump_slo(
            local_path=local_path,
            object_name=object_name,
            metadata=metadata,
            cfg=cfg,
            password=password,
            file_size=file_size,
            segment_size=_slo_segment_size(cfg),
            log_event=log_event,
        )


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
    """Download a single JSON object from Swift as raw bytes (full load)."""
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

    For SLO objects, Swift transparently concatenates the segments at
    GET time, so the analyst sees a single stream of bytes regardless
    of upload method.
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
# Private — single PUT path (file < threshold)
# ---------------------------------------------------------------------------

def _upload_dump_simple(
    local_path: Path,
    object_name: str,
    metadata: dict,
    cfg,
    password: str,
    file_size: int,
    log_event: Optional[Callable[[str, dict], None]],
) -> dict:
    """Single-PUT upload: existing pre-Feature-2 behaviour, refactored."""
    container = cfg.swift_container

    _emit(log_event, "swift_upload_started", {
        "object_name":   object_name,
        "container":     container,
        "size_bytes":    file_size,
        "upload_method": "single_put",
    })

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
        "upload_method": "single_put",
        "slo_segments":  None,
    }


# ---------------------------------------------------------------------------
# Private — SLO path (file >= threshold)
# ---------------------------------------------------------------------------

class _HashingLimitedReader:
    """File-like wrapper for a single SLO segment.

    Wraps an open file handle and exposes ``read()`` that returns at most
    ``limit`` bytes total across all calls, while updating an internal
    MD5 hash with every byte handed to the caller. swiftclient streams
    a segment by repeatedly calling ``read(chunk_size)`` on this object,
    so by the time the PUT completes we have:

      * MD5 of the segment computed locally (single I/O pass)
      * exactly ``limit`` bytes consumed from the underlying file
      * underlying file positioned at the start of the next segment

    Memory footprint: O(chunk_size) — never the full segment.
    """

    def __init__(self, fh, limit):
        self._fh = fh
        self._remaining = limit
        self._md5 = hashlib.md5()
        self._bytes_read = 0

    def read(self, size=-1):
        if self._remaining <= 0:
            return b""
        if size is None or size < 0:
            to_read = self._remaining
        else:
            to_read = min(size, self._remaining)
        data = self._fh.read(to_read)
        self._remaining -= len(data)
        self._bytes_read += len(data)
        self._md5.update(data)
        return data

    @property
    def hexdigest(self):
        return self._md5.hexdigest()

    @property
    def bytes_read(self):
        return self._bytes_read


def _upload_dump_slo(
    local_path: Path,
    object_name: str,
    metadata: dict,
    cfg,
    password: str,
    file_size: int,
    segment_size: int,
    log_event: Optional[Callable[[str, dict], None]],
) -> dict:
    """SLO upload: split, segment PUTs, manifest PUT, composite verify, cleanup."""
    container = cfg.swift_container
    segments_container = container + SEGMENTS_CONTAINER_SUFFIX

    n_segments = math.ceil(file_size / segment_size)
    expected_md5 = metadata.get("md5", "")
    expected_sha1 = metadata.get("sha1", "")

    log.info(
        "SLO upload: %d segments of up to %.2f GiB each (last %.2f GiB)",
        n_segments,
        segment_size / (1024 ** 3),
        (file_size - segment_size * (n_segments - 1)) / (1024 ** 3),
    )

    _emit(log_event, "slo_upload_started", {
        "object_name":         object_name,
        "container":           container,
        "segments_container":  segments_container,
        "size_bytes":          file_size,
        "segment_size":        segment_size,
        "segment_count":       n_segments,
        "upload_method":       "slo",
    })

    url, token = _authenticate(cfg, password)
    _ensure_container(url, token, container)
    _ensure_container(url, token, segments_container)

    uploaded: list[dict] = []  # one dict per successfully uploaded segment

    try:
        with local_path.open("rb") as fh:
            for i in range(1, n_segments + 1):
                # Last segment may be smaller than segment_size.
                remaining_in_file = file_size - segment_size * (i - 1)
                this_segment_size = min(segment_size, remaining_in_file)

                seg_short_name = f"seg-{i:04d}"
                seg_full_name = f"{object_name}/{seg_short_name}"

                reader = _HashingLimitedReader(fh, this_segment_size)

                seg_etag = swiftclient.client.put_object(
                    url=url,
                    token=token,
                    container=segments_container,
                    name=seg_full_name,
                    contents=reader,
                    content_length=this_segment_size,
                    chunk_size=_SEGMENT_READ_CHUNK,
                )
                seg_etag_clean = (seg_etag or "").strip('"')
                seg_md5 = reader.hexdigest

                # Register the segment as 'uploaded on Swift' BEFORE running
                # integrity checks. Reasoning: the PUT has already landed
                # bytes on Swift; whether or not the bytes are trustworthy,
                # they exist server-side and the cleanup branch must delete
                # them when an integrity check raises below.
                uploaded.append({
                    "name":  seg_full_name,
                    "etag":  seg_etag_clean,
                    "size":  this_segment_size,
                    "md5":   seg_md5,
                    "index": i,
                })

                # Sanity checks AFTER the segment is registered for cleanup.
                if reader.bytes_read != this_segment_size:
                    raise IntegrityError(
                        f"Segment {seg_full_name}: read {reader.bytes_read} "
                        f"bytes, expected {this_segment_size}"
                    )
                if seg_etag_clean.lower() != seg_md5.lower():
                    raise IntegrityError(
                        f"Segment {seg_full_name}: swift etag={seg_etag_clean} "
                        f"!= local md5={seg_md5}"
                    )

                log.info(
                    "SLO segment %d/%d uploaded: %s (%.2f GiB, etag=%s)",
                    i, n_segments, seg_full_name,
                    this_segment_size / (1024 ** 3), seg_etag_clean,
                )
                _emit(log_event, "swift_segment_uploaded", {
                    "segment_name":       seg_full_name,
                    "segments_container": segments_container,
                    "etag":               seg_etag_clean,
                    "md5":                seg_md5,
                    "size_bytes":         this_segment_size,
                    "index":              i,
                    "total":              n_segments,
                })

        # Build SLO manifest. The SLO spec requires keys 'path', 'etag',
        # 'size_bytes' for each segment; 'path' uses the ABSOLUTE form
        # '/<container>/<object>'.
        manifest = [
            {
                "path":       f"/{segments_container}/{seg['name']}",
                "etag":       seg["etag"],
                "size_bytes": seg["size"],
            }
            for seg in uploaded
        ]
        manifest_bytes = json.dumps(manifest).encode("utf-8")

        # Manifest headers carry the forensic seal.
        manifest_headers = {f"X-Object-Meta-{k}": str(v) for k, v in metadata.items()}
        manifest_headers["X-Object-Meta-Global-Md5"]  = expected_md5
        manifest_headers["X-Object-Meta-Global-Sha1"] = expected_sha1

        # PUT the manifest synchronously (no heartbeat=on). Swift returns
        # 201 Created with the composite Etag in the response header;
        # swiftclient parses it and returns it as the function value.
        # See the module docstring for the heartbeat-vs-synchronous
        # rationale.
        manifest_etag_raw = swiftclient.client.put_object(
            url=url,
            token=token,
            container=container,
            name=object_name,
            contents=manifest_bytes,
            content_type="application/json",
            query_string="multipart-manifest=put",
            headers=manifest_headers,
        )
        manifest_etag = (manifest_etag_raw or "").strip('"')

        # Robustness: if swiftclient still didn't return an etag (some
        # library versions return None even on 201), fall back to a HEAD
        # on the just-created manifest object. The Etag header on a HEAD
        # of an SLO manifest is the composite etag, exactly what we need.
        if not manifest_etag:
            log.warning(
                "manifest PUT returned no etag; falling back to HEAD on %s/%s",
                container, object_name,
            )
            try:
                head_resp = swiftclient.client.head_object(
                    url=url,
                    token=token,
                    container=container,
                    object_name=object_name,
                )
                manifest_etag = (head_resp.get("etag") or "").strip('"')
                log.info(
                    "manifest etag recovered from HEAD: %s",
                    manifest_etag,
                )
            except Exception as exc:  # noqa: BLE001
                log.error("HEAD fallback failed: %s", exc)
                raise IntegrityError(
                    f"could not retrieve manifest etag for {object_name}: "
                    f"PUT returned empty and HEAD failed ({exc})"
                ) from exc

        log.info("SLO manifest uploaded: etag=%s", manifest_etag)

        _emit(log_event, "swift_manifest_uploaded", {
            "object_name":     object_name,
            "container":       container,
            "manifest_etag":   manifest_etag,
            "segments_count":  n_segments,
        })

        # Composite etag verification.
        # Compute locally: md5(concat(seg_etag_ascii_bytes))
        composite_local = _compute_composite_etag([s["etag"] for s in uploaded])
        
        # Swift returns just the hash on PUT manifest response, not the -N suffix.
        # We strip the -N from our local composite if we appended it, or just 
        # compare the raw hashes directly.
        # Remove any quotes or whitespace from swift's response
        swift_composite = manifest_etag.strip('"\'-') 
        
        composite_match = (swift_composite.lower() == composite_local.lower())

        _emit(log_event, "swift_slo_upload_verified", {
            "object_name":          object_name,
            "container":            container,
            "composite_etag_match": composite_match,
            "computed_composite":   composite_local,
            "swift_composite":      swift_composite,
            "segments_count":       n_segments,
        })

        if not composite_match:
            raise IntegrityError(
                f"SLO composite etag mismatch for {object_name}: "
                f"computed={composite_local} "
                f"swift={swift_composite}"
            )

        return {
            "swift_object":  f"{container}/{object_name}",
            "swift_etag":    manifest_etag,
            "etag_verified": True,
            "size_bytes":    file_size,
            "upload_method": "slo",
            "slo_segments":  uploaded,
        }

    except Exception as exc:
        # Cleanup: delete every segment we uploaded so far. Best effort —
        # delete failures are logged as warnings but do not mask the
        # original exception.
        log.warning(
            "SLO upload failed (%s); cleaning up %d segments",
            exc, len(uploaded),
        )
        _cleanup_segments(
            url, token, segments_container,
            [s["name"] for s in uploaded],
            log_event,
        )
        raise


def _compute_composite_etag(segment_etags: list[str]) -> str:
    """Swift SLO composite etag = md5( concat(seg_etag_ascii_bytes) )."""
    h = hashlib.md5()
    for e in segment_etags:
        h.update(e.encode("ascii"))
    return h.hexdigest()


def _cleanup_segments(
    url: str,
    token: str,
    segments_container: str,
    segment_names: list[str],
    log_event: Optional[Callable[[str, dict], None]],
) -> None:
    """Best-effort delete of orphan segments after a failed SLO upload."""
    deleted = 0
    failed = 0
    for name in segment_names:
        try:
            swiftclient.client.delete_object(
                url=url,
                token=token,
                container=segments_container,
                name=name,
            )
            deleted += 1
        except swiftclient.exceptions.ClientException as exc:
            log.warning(
                "could not delete orphan segment %s/%s: %s",
                segments_container, name, exc,
            )
            failed += 1
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "unexpected error deleting orphan segment %s/%s: %s",
                segments_container, name, exc,
            )
            failed += 1

    log.info(
        "SLO cleanup: %d segments deleted, %d failed",
        deleted, failed,
    )
    _emit(log_event, "slo_cleanup_completed", {
        "segments_container": segments_container,
        "attempted":          len(segment_names),
        "deleted":             deleted,
        "failed":              failed,
    })


# ---------------------------------------------------------------------------
# Private helpers (auth, container, etag verify, password resolution)
# ---------------------------------------------------------------------------

def _authenticate(cfg, password: str) -> Tuple[str, str]:
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


def _slo_segment_size(cfg) -> int:
    """Read SLO segment size from cfg, with default fallback.

    The Config dataclass exposes swift_slo_segment_size_bytes (int).
    """
    return getattr(cfg, "swift_slo_segment_size_bytes", DEFAULT_SLO_SEGMENT_SIZE)


def _slo_threshold(cfg) -> int:
    """SLO activation threshold.

    By design the threshold equals the segment size: a file at the threshold
    is exactly one full segment, files smaller than that fit a single PUT.
    """
    return _slo_segment_size(cfg)


def _emit(
    log_event: Optional[Callable[[str, dict], None]],
    event_type: str,
    data: dict,
) -> None:
    log.debug("coc_event %s: %s", event_type, data)
    if log_event is not None:
        log_event(event_type, data)
