"""ForensicNova — streaming hash computation for forensic memory dumps.

Computes MD5 and SHA-1 over an arbitrarily large file in a single I/O pass,
using fixed-size chunks so that RAM consumption is O(1) regardless of the
dump size.

Design decisions:
- Single pass: both hash objects are updated in the same read loop.
  Two separate passes on a 16 GB file would mean reading 32 GB from disk.
- Chunk size 64 KB: large enough to amortise syscall overhead, small enough
  to stay well within any L2/L3 cache line. Benchmarks on NVMe and spinning
  rust both plateau around this value.
- Optional log_event callable: keeps this module decoupled from the
  chain-of-custody module (reports/chain_of_custody.py) that will be built
  later. Pass None (default) for standalone use; pass chain_of_custody.log_event
  when wiring the full acquisition pipeline in app/api/v1.py.

Usage:
    from app.hashing.hasher import compute_hashes

    result = compute_hashes(Path("/var/lib/forensicnova/acquisitions/abc/dump.raw"))
    # result == {"md5": "d41d8...", "sha1": "da39a3...", "size_bytes": 4294967296}
"""
from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import Callable, Optional

log = logging.getLogger("forensicnova.hashing")

# Read buffer: 64 KB per iteration — O(1) RAM, optimal throughput.
_CHUNK_SIZE = 64 * 1024  # 64 KB


def compute_hashes(
    path: Path,
    log_event: Optional[Callable[[str, dict], None]] = None,
) -> dict:
    """Compute MD5 and SHA-1 over *path* in a single streaming pass.

    :param path:       Absolute path to the raw memory dump on the hypervisor.
    :param log_event:  Optional chain-of-custody callback with signature
                       ``log_event(event_type: str, data: dict) -> None``.
                       Called at hashing_started and hashing_completed.
                       Pass None to skip chain-of-custody logging (default).

    :returns: dict with keys:
        - ``md5``        (str)  — hex-encoded MD5 digest
        - ``sha1``       (str)  — hex-encoded SHA-1 digest
        - ``size_bytes`` (int)  — total bytes read (sanity cross-check)

    :raises FileNotFoundError: if *path* does not exist.
    :raises PermissionError:   if the process cannot read *path*.
    :raises OSError:           for other I/O failures during reading.
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"dump not found: {path}")

    if not path.is_file():
        raise ValueError(f"path is not a regular file: {path}")

    log.info("hashing started: %s", path)
    if log_event is not None:
        log_event("hashing_started", {"path": str(path)})

    md5_obj = hashlib.md5()
    sha1_obj = hashlib.sha1()
    size_bytes = 0
    t_start = time.monotonic()

    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_CHUNK_SIZE)
            if not chunk:
                break
            md5_obj.update(chunk)
            sha1_obj.update(chunk)
            size_bytes += len(chunk)

    duration = time.monotonic() - t_start
    throughput_mb = (size_bytes / 1024 / 1024) / duration if duration > 0 else 0

    md5_hex = md5_obj.hexdigest()
    sha1_hex = sha1_obj.hexdigest()

    log.info(
        "hashing completed: size=%d bytes, md5=%s, sha1=%s, "
        "duration=%.1fs, throughput=%.1f MB/s",
        size_bytes, md5_hex, sha1_hex, duration, throughput_mb,
    )

    if log_event is not None:
        log_event(
            "hashing_completed",
            {
                "path": str(path),
                "size_bytes": size_bytes,
                "md5": md5_hex,
                "sha1": sha1_hex,
                "duration_seconds": round(duration, 3),
            },
        )

    return {
        "md5": md5_hex,
        "sha1": sha1_hex,
        "size_bytes": size_bytes,
    }
