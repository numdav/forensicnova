"""ForensicNova — No-op analyzer.

The simplest possible analyzer. Reads the dump end-to-end and
recomputes MD5+SHA1 on the fly, then compares with the hashes
declared by the acquisition report. Returns a structured dict with
the computation results plus a single boolean `hashes_match_report`
flag.

Forensic justification — "triple-witness" coherence:

  In a correctly behaving deployment the same MD5+SHA1 pair is
  computed in three independent contexts:

    1. Acquisition backend, while writing the dump locally before
       upload (`app/storage/hasher.py` single-pass during libvirt
       coreDump). This is the canonical chain-of-custody hash —
       stored in the v1.2 report under report["dump"]["md5/sha1"]
       and used as the Swift X-Object-Meta-* annotation.

    2. Analyzer Swift client, while downloading the dump from
       Swift to the working directory (single-pass during streaming
       in swift.download_dump_with_hashes). Compared against (1)
       by swift.verify_dump_hashes — the standard integrity check
       wired into the runner's `verifying_hash` phase.

    3. NoOpAnalyzer (this module), while reading the dump from the
       local filesystem just before "analysis" begins. Compared
       against (1) via the report. A mismatch here would mean the
       file on disk has been altered between download time and
       analysis time — bit rot, filesystem corruption, or worse,
       active tampering. This is an additional defense-in-depth
       layer, not a strict redundancy: it cannot be silenced by
       breaking just the download path.

  Witnesses (1) and (2) plus this third one effectively create a
  signed log of the dump's bytes across three time frames, all
  derived from the same content. A discrepancy at stage 3 is a
  forensically significant event and should be surfaced to the
  operator rather than silently masked.

Failure policy:

  NoOpAnalyzer DOES NOT raise on hash mismatch. It returns the
  result with `hashes_match_report: False` plus a `mismatch` sub-dict
  showing computed vs expected. The async runner (E2.4) decides
  whether to fail the job — typically yes, but the policy may differ
  for advanced workflows (e.g. "analyze anyway, but mark the
  analysis as quarantined").

  Real I/O failures (file not found, unreadable, empty) DO raise the
  standard built-in exceptions (FileNotFoundError, OSError); the
  runner catches them in its top-level try/except and converts them
  into PHASE_FAILED.
"""
from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path

log = logging.getLogger("forensicnova_analyzer.analyzers.noop")

# Streaming read chunk size. 1 MiB matches swift.py's download chunk
# size, so the hashers see one chunk per HTTP read in the producer
# context too — keeps the I/O profile consistent across the pipeline.
_HASH_CHUNK_SIZE = 1024 * 1024  # 1 MiB


class NoOpAnalyzer:
    """Triple-witness coherence analyzer.

    Stateful only across the lifetime of a single `run()` invocation.
    Instances are cheap; the runner can create one per job without
    worrying about reuse semantics.
    """

    # Identification surfaced in the result dict and (later) in the
    # Swift object name produced by upload_analysis_json.
    name = "noop"
    version = "0.1.0"

    def run(
        self,
        dump_path: Path,
        expected_md5: str,
        expected_sha1: str,
        chunk_size: int = _HASH_CHUNK_SIZE,
    ) -> dict:
        """Read the dump and produce a coherence-check result dict.

        :param dump_path:    absolute path to the dump file on local disk
        :param expected_md5: hex MD5 declared by the acquisition report
                             (i.e. summary["dump_md5"] in E2.4)
        :param expected_sha1: hex SHA1 declared by the acquisition report
                             (i.e. summary["dump_sha1"] in E2.4)
        :param chunk_size:   read chunk size in bytes (default 1 MiB)

        :returns: dict with the following keys:

            analyzer              (str) : "noop"
            analyzer_version      (str) : "0.1.0"
            dump_path             (str) : absolute path read
            dump_size_bytes       (int) : total bytes read
            dump_md5              (str) : hex MD5 computed by this analyzer
            dump_sha1             (str) : hex SHA1 computed by this analyzer
            duration_seconds      (float) : wall-clock time of run()
            throughput_mib_per_s  (float) : derived MiB/s read speed
            hashes_match_report   (bool) : True iff both computed hashes
                                           equal the expected ones
            mismatch              (dict | None) : present only when
                                                  hashes_match_report is
                                                  False; sub-keys
                                                  expected_md5, computed_md5,
                                                  expected_sha1, computed_sha1.

        :raises FileNotFoundError: if `dump_path` does not exist.
        :raises OSError: on other I/O failures during read.
        """
        dump_path = Path(dump_path)
        if not dump_path.is_file():
            raise FileNotFoundError(f"dump file not found: {dump_path}")

        log.info(
            "[noop] starting: dump=%s expected_md5=%s expected_sha1=%s",
            dump_path,
            (expected_md5 or "")[:8] + "..." if expected_md5 else "<empty>",
            (expected_sha1 or "")[:8] + "..." if expected_sha1 else "<empty>",
        )

        md5_hasher = hashlib.md5()
        sha1_hasher = hashlib.sha1()
        size_bytes = 0

        # Use monotonic() for elapsed time so a wall-clock adjustment
        # (NTP step, etc.) cannot produce a negative duration.
        t0 = time.monotonic()

        with dump_path.open("rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                md5_hasher.update(chunk)
                sha1_hasher.update(chunk)
                size_bytes += len(chunk)

        duration = time.monotonic() - t0

        computed_md5 = md5_hasher.hexdigest()
        computed_sha1 = sha1_hasher.hexdigest()

        # Case-insensitive comparison — Swift/Glance/our own report
        # already store lowercase hex, but a 3rd-party producer might
        # not, and a case mismatch is not a real mismatch.
        em = (expected_md5 or "").lower()
        es = (expected_sha1 or "").lower()
        md5_ok = computed_md5 == em
        sha1_ok = computed_sha1 == es
        hashes_match = bool(em and es and md5_ok and sha1_ok)

        throughput_mib_s = (
            (size_bytes / (1024 * 1024)) / duration if duration > 0 else 0.0
        )

        result: dict = {
            "analyzer":             self.name,
            "analyzer_version":     self.version,
            "dump_path":            str(dump_path),
            "dump_size_bytes":      size_bytes,
            "dump_md5":             computed_md5,
            "dump_sha1":            computed_sha1,
            "duration_seconds":     round(duration, 3),
            "throughput_mib_per_s": round(throughput_mib_s, 2),
            "hashes_match_report":  hashes_match,
        }

        if not hashes_match:
            result["mismatch"] = {
                "expected_md5":  em,
                "computed_md5":  computed_md5,
                "md5_match":     md5_ok,
                "expected_sha1": es,
                "computed_sha1": computed_sha1,
                "sha1_match":    sha1_ok,
            }
            log.warning(
                "[noop] HASH MISMATCH dump=%s md5_match=%s sha1_match=%s",
                dump_path, md5_ok, sha1_ok,
            )
        else:
            log.info(
                "[noop] completed: %.3f s, %.1f MiB/s, hashes match report",
                duration, throughput_mib_s,
            )

        return result
