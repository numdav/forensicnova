"""ForensicNova Analyzer — async analysis runner.

Spawns a daemon thread that runs the full analyzer pipeline for one
job: locates the acquisition report in Swift, downloads (or reuses
from cache) the dump file locally, performs the triple-witness
coherence check, dispatches to the requested analyzer, uploads the
result JSON back to Swift, finalises the job record.

Pipeline ordering:
    1.  PHASE_DOWNLOADING_DUMP — fetch acquisition report from Swift,
                                  summarize it, then either reuse the
                                  cached dump or download a fresh copy
                                  (with per-segment progress callback).
    2.  PHASE_VERIFYING_HASH    — confirm MD5+SHA1 of downloaded bytes
                                  match the values in the acquisition
                                  report. This is the second-witness
                                  check. On cache hit the same check
                                  happens in step 1 to validate the
                                  cached file before reuse.
    3.  PHASE_RUNNING_ANALYZER  — dispatch to the analyzer class
                                  (currently only NoOpAnalyzer). The
                                  analyzer recomputes hashes a third
                                  time (third witness) and returns a
                                  result dict.
    4.  PHASE_UPLOADING_RESULTS — build the v1.0 analysis JSON,
                                  serialize, upload to Swift, attach
                                  analysis_id to the job record.
    5.  STATUS_COMPLETED        — final complete_job(result).

Caching:
    Downloaded dumps live under <cfg.work_dir>/cache/<acquisition_id>/
    so subsequent analyses on the same acquisition (e.g. fast Vol3
    preset followed by a custom plugin selection) reuse the local copy.
    Cache hits still re-verify hashes (a third- and fourth-witness
    chain on every analysis), so the cache is a performance
    optimisation and never a soundness shortcut.

    A per-acquisition RLock serialises concurrent jobs that target the
    same acquisition_id. This prevents two workers from racing on the
    cache directory, while jobs on different acquisitions continue to
    run in parallel.

    Eviction is simple: before downloading a fresh dump, if free space
    is below CACHE_MIN_FREE_GB the runner deletes cached acquisitions
    in oldest-first order until enough space is reclaimed. No time
    expiry, no LRU sophistication — keep it predictable.

Concurrency:
    Unlike the acquisition backend (which serialises libvirt
    coreDumpWithFormat with a module-level lock because QEMU is the
    bottleneck), the analyzer can run several analyses concurrently:
    they are CPU/RAM bound but on a multi-core box that scales fine.
    No global lock — only the per-acquisition cache lock described
    above.

Errors:
    Specific exception types are caught and translated into clear
    jobs.fail_job() messages. The cache directory of the job is left
    intact on failure so a re-run can profit from any partial state
    (e.g. a successfully downloaded dump even if the analyzer crashed).
"""
from __future__ import annotations

import hashlib
import logging
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from forensicnova_analyzer import swift
from forensicnova_analyzer.analyzers import NoOpAnalyzer, VolatilityAnalyzer
from forensicnova_analyzer.jobs import (
    JobManager,
    PHASE_DOWNLOADING_DUMP,
    PHASE_RUNNING_ANALYZER,
    PHASE_UPLOADING_RESULTS,
    PHASE_VERIFYING_HASH,
)

log = logging.getLogger("forensicnova_analyzer.jobs_runner")

# Analysis JSON schema version emitted by this runner. Bumped when the
# top-level structure changes; consumers should ignore unknown keys.
ANALYSIS_SCHEMA_VERSION = "1.0"

# Minimum free space on the work_dir filesystem before downloading a
# fresh dump. Below this threshold the runner evicts cached
# acquisitions in oldest-first order. 20 GiB is enough for ~5 fresh
# 4 GiB dumps on the DevStack volume.
#
# TODO(E2.5+): expose as [analyzer] cache_min_free_gb in the INI.
CACHE_MIN_FREE_GB = 20

# Chunk size for the cache pre-check hashing. Same value as
# swift.download_dump_with_hashes and analyzers.noop, so the I/O
# profile is identical across cache-hit and cache-miss paths.
_HASH_CHUNK_SIZE = 1024 * 1024  # 1 MiB

# Per-acquisition lock dict. Protects the cache directory against
# concurrent download/verify on the same acquisition_id while
# allowing parallelism across acquisitions.
_acquisition_locks: dict[str, threading.RLock] = {}
_acquisition_locks_dict_lock = threading.Lock()


def _lock_for_acquisition(acquisition_id: str) -> threading.RLock:
    """Return the per-acquisition RLock, creating it on first access."""
    with _acquisition_locks_dict_lock:
        lock = _acquisition_locks.get(acquisition_id)
        if lock is None:
            lock = threading.RLock()
            _acquisition_locks[acquisition_id] = lock
        return lock


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _utc_now_compact() -> str:
    """Compact UTC timestamp for object names: 20260524T143052Z."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start_analysis_job(
    *,
    cfg,
    jobs: JobManager,
    job_id: str,
    acquisition_id: str,
    analyzer_name: str,
    operator: str,
    preset: Optional[str] = None,
    plugins: Optional[list[str]] = None,
) -> threading.Thread:
    """Spawn the worker thread for an analysis job and return it.

    The job record must already exist (created by the HTTP endpoint
    via jobs.create_job(...)). This function just attaches a thread
    that drives it through the pipeline.
    """
    t = threading.Thread(
        target=_run_analysis,
        kwargs={
            "cfg":            cfg,
            "jobs":           jobs,
            "job_id":         job_id,
            "acquisition_id": acquisition_id,
            "analyzer_name":  analyzer_name,
            "operator":       operator,
            "preset":         preset,
            "plugins":        plugins,
        },
        name=f"forensicnova-analysis-{job_id[:8]}",
        daemon=True,
    )
    t.start()
    return t


def delete_acquisition_cache(acquisition_id: str, cfg) -> dict:
    """Forcibly evict an acquisition's cached dump.

    Acquires the per-acquisition lock first so we don't race with a
    job currently downloading or verifying. Returns a dict describing
    what was deleted (or that the cache was already empty).
    """
    cache_dir = Path(cfg.work_dir) / "cache" / acquisition_id
    with _lock_for_acquisition(acquisition_id):
        if not cache_dir.exists():
            return {"acquisition_id": acquisition_id, "deleted": False,
                    "reason": "no cache directory"}
        size_bytes = _dir_size_bytes(cache_dir)
        shutil.rmtree(cache_dir)
        log.info(
            "cache evicted on demand: %s (freed %.1f MiB)",
            cache_dir, size_bytes / (1024 * 1024),
        )
        return {
            "acquisition_id":   acquisition_id,
            "deleted":          True,
            "freed_bytes":      size_bytes,
            "freed_mib":        round(size_bytes / (1024 * 1024), 1),
        }


# ---------------------------------------------------------------------------
# Internal pipeline
# ---------------------------------------------------------------------------

def _run_analysis(
    cfg,
    jobs: JobManager,
    job_id: str,
    acquisition_id: str,
    analyzer_name: str,
    operator: str,
    preset: Optional[str],
    plugins: Optional[list[str]],
) -> None:
    """Full analysis pipeline, executed in a background daemon thread."""
    log.info(
        "[job=%s] analysis worker started (acq=%s, analyzer=%s, preset=%s)",
        job_id, acquisition_id, analyzer_name, preset,
    )

    started_at = _utc_now_iso()

    try:
        # ----- Acquire the acquisition report and summarize it -----
        report = swift.find_acquisition(acquisition_id, cfg)
        if report is None:
            raise FileNotFoundError(
                f"acquisition_id {acquisition_id} not found in Swift"
            )
        summary = swift.summarize_acquisition(report)

        # ----- PHASE: downloading_dump (with cache lookup) -----
        # The cache lock guarantees that two concurrent jobs on the same
        # acquisition serialise on the cache directory; the lock is
        # held for the whole download+verify section.
        with _lock_for_acquisition(acquisition_id):
            dump_path = _ensure_dump_local(
                cfg=cfg,
                summary=summary,
                jobs=jobs,
                job_id=job_id,
            )

            # ----- PHASE: verifying_hash -----
            # If we got a cache hit, _ensure_dump_local already
            # validated the hashes. We still run an explicit phase
            # marker here so the dashboard timeline shows the step.
            jobs.update_phase(
                job_id, PHASE_VERIFYING_HASH,
                "Verifying MD5+SHA1 against acquisition report",
            )
            # Hash check is now implicit (already done above), but
            # we emit a debug log so the trace is unambiguous.
            log.debug(
                "[job=%s] hash coherence already confirmed during "
                "_ensure_dump_local", job_id,
            )

        # ----- PHASE: running_analyzer -----
        jobs.update_phase(
            job_id, PHASE_RUNNING_ANALYZER,
            f"Running {analyzer_name} analyzer",
        )

        # Per-plugin progress callback for the dashboard watch page.
        # The VolatilityAnalyzer invokes this BEFORE starting each
        # plugin's subprocess, so the user sees what the analyzer is
        # currently doing (e.g. "Running plugin 12/34: windows.malware.
        # malfind.Malfind") instead of a static "Running volatility
        # analyzer" label for the entire 8-15 minute full-preset run.
        #
        # Captures job_id and jobs from the enclosing scope. The
        # JobManager's update_label is the canonical fine-grained
        # progress signal (documented in jobs.py as "e.g. Vol3
        # per-plugin"), so the dashboard's existing label rendering
        # picks this up via the standard 3-second poll without any
        # template changes.
        #
        # Analyzers that do not invoke plugins (noop) silently ignore
        # the callback; the parameter is keyword-only and Optional.
        def _progress(plugin_name: str, idx: int, total: int) -> None:
            jobs.update_label(
                job_id,
                f"Running plugin {idx}/{total}: {plugin_name}",
            )

        result = _dispatch_analyzer(
            analyzer_name=analyzer_name,
            dump_path=dump_path,
            summary=summary,
            preset=preset,
            plugins=plugins,
            cfg=cfg,
            on_progress=_progress,
        )

        # Strict coherence policy: if the analyzer says hashes do not
        # match the report, fail the job. The dump on disk has likely
        # been tampered with or corrupted between download and
        # analysis; the result cannot be trusted as forensic evidence.
        if not result.get("hashes_match_report"):
            mismatch = result.get("mismatch", {})
            raise swift.IntegrityError(
                f"analyzer-side hash mismatch — {mismatch}"
            )

        # ----- PHASE: uploading_results -----
        jobs.update_phase(
            job_id, PHASE_UPLOADING_RESULTS,
            "Uploading analysis result to Swift",
        )
        completed_at = _utc_now_iso()

        analysis_object_name = _build_analysis_object_name(
            analyzer=analyzer_name,
            preset=preset,
            acquisition_id=acquisition_id,
            job_id=job_id,
        )
        analysis_json = _build_analysis_json(
            analysis_id=analysis_object_name,
            analyzer=analyzer_name,
            analyzer_version=result.get("analyzer_version", "unknown"),
            preset=preset,
            plugins=plugins,
            acquisition_id=acquisition_id,
            operator=operator,
            started_at=started_at,
            completed_at=completed_at,
            summary=summary,
            analyzer_result=result,
        )

        upload_metadata = {
            "analysis_id":    analysis_object_name,
            "analyzer":       analyzer_name,
            "preset":         preset or "",
            "acquisition_id": acquisition_id,
            "operator":       operator,
            "schema_version": ANALYSIS_SCHEMA_VERSION,
        }
        upload_result = swift.upload_analysis_json(
            json_bytes=analysis_json,
            object_name=analysis_object_name,
            metadata=upload_metadata,
            cfg=cfg,
        )

        jobs.update_analysis_id(job_id, analysis_object_name)

        # ----- COMPLETED -----
        jobs.complete_job(job_id, {
            "analysis_id":       analysis_object_name,
            "swift_object":      upload_result["swift_object"],
            "swift_etag":        upload_result["swift_etag"],
            "size_bytes":        upload_result["size_bytes"],
            "duration_seconds":  result.get("duration_seconds"),
            "hashes_match_report": True,  # we'd have failed otherwise
        })
        log.info(
            "[job=%s] DONE: analysis_id=%s size=%d",
            job_id, analysis_object_name, upload_result["size_bytes"],
        )

    except swift.SwiftObjectNotFound as exc:
        log.error("[job=%s] swift object not found: %s", job_id, exc)
        jobs.fail_job(job_id, f"Swift object not found: {exc}")

    except swift.UnsupportedReportSchema as exc:
        log.error("[job=%s] unsupported report schema: %s", job_id, exc)
        jobs.fail_job(job_id, f"Unsupported acquisition report schema: {exc}")

    except swift.IntegrityError as exc:
        log.error("[job=%s] integrity failure: %s", job_id, exc)
        jobs.fail_job(job_id, f"Integrity verification failed: {exc}")

    except FileNotFoundError as exc:
        log.error("[job=%s] file not found: %s", job_id, exc)
        jobs.fail_job(job_id, f"File not found: {exc}")

    except (PermissionError, OSError) as exc:
        log.error("[job=%s] filesystem error: %s", job_id, exc)
        jobs.fail_job(job_id, f"Filesystem error: {exc}")

    except Exception as exc:  # noqa: BLE001
        log.exception("[job=%s] unexpected error", job_id)
        jobs.fail_job(job_id, f"Internal error: {exc}")


# ---------------------------------------------------------------------------
# Cache management
# ---------------------------------------------------------------------------

def _ensure_dump_local(
    cfg,
    summary: dict,
    jobs: JobManager,
    job_id: str,
) -> Path:
    """Return a Path to the local dump for this acquisition.

    Caller MUST hold the per-acquisition lock.

    Strategy:
      1. If a cached file exists, recompute MD5+SHA1 on it. If they
         match the report -> cache hit, return the path.
         If they don't -> evict the cache dir, fall through.
      2. Otherwise: check free space, evict oldest cached dumps
         if necessary, download fresh from Swift, return the path.
    """
    acquisition_id = summary["acquisition_id"]
    cache_dir = Path(cfg.work_dir) / "cache" / acquisition_id
    dump_path = cache_dir / "dump.raw"

    if dump_path.exists():
        # Candidate cache hit — verify it before trusting.
        jobs.update_phase(
            job_id, PHASE_DOWNLOADING_DUMP,
            "Local cache hit — verifying integrity before reuse",
        )
        log.info("[job=%s] cache candidate found: %s", job_id, dump_path)
        local = _compute_md5_sha1(dump_path)
        try:
            swift.verify_dump_hashes(
                computed_md5=local["md5"],
                computed_sha1=local["sha1"],
                expected_md5=summary["dump_md5"],
                expected_sha1=summary["dump_sha1"],
            )
            log.info(
                "[job=%s] cache hit confirmed: %s (%d bytes)",
                job_id, dump_path, local["size_bytes"],
            )
            return dump_path
        except swift.IntegrityError as exc:
            log.warning(
                "[job=%s] cached dump failed integrity check, evicting: %s",
                job_id, exc,
            )
            shutil.rmtree(cache_dir, ignore_errors=True)

    # Cache miss (or invalidated). Make room if needed, then download.
    jobs.update_phase(
        job_id, PHASE_DOWNLOADING_DUMP,
        "Downloading dump from Swift",
    )
    _evict_if_low_space(cfg=cfg, exclude_acquisition_id=acquisition_id)

    cache_dir.mkdir(parents=True, exist_ok=True)

    def _progress(label: str) -> None:
        jobs.update_label(job_id, label)

    downloaded = swift.download_dump_with_hashes(
        object_name=summary["dump_object_name"],
        dest_path=dump_path,
        cfg=cfg,
        progress_callback=_progress,
    )
    # Verify hashes right after download. If this fails the cache
    # directory is removed so a retry will re-download cleanly.
    try:
        swift.verify_dump_hashes(
            computed_md5=downloaded["md5"],
            computed_sha1=downloaded["sha1"],
            expected_md5=summary["dump_md5"],
            expected_sha1=summary["dump_sha1"],
        )
    except swift.IntegrityError:
        shutil.rmtree(cache_dir, ignore_errors=True)
        raise

    log.info(
        "[job=%s] downloaded and cached: %s (%d bytes)",
        job_id, dump_path, downloaded["size_bytes"],
    )
    return dump_path


def _evict_if_low_space(cfg, exclude_acquisition_id: str) -> None:
    """Delete oldest cached acquisitions until free space is OK.

    The acquisition_id we're about to download for is excluded from
    the eviction list — we don't want to delete the directory we're
    about to write into.
    """
    cache_root = Path(cfg.work_dir) / "cache"
    cache_root.mkdir(parents=True, exist_ok=True)

    free_gb = _free_gb(cache_root)
    if free_gb >= CACHE_MIN_FREE_GB:
        return

    log.warning(
        "low free space on %s: %.1f GiB available (threshold %d GiB), "
        "evicting old cache entries",
        cache_root, free_gb, CACHE_MIN_FREE_GB,
    )

    # Build (mtime, dir) list excluding the target acquisition.
    candidates: list[tuple[float, Path]] = []
    for sub in cache_root.iterdir():
        if not sub.is_dir():
            continue
        if sub.name == exclude_acquisition_id:
            continue
        candidates.append((sub.stat().st_mtime, sub))
    candidates.sort(key=lambda t: t[0])  # oldest first

    for _mtime, sub in candidates:
        if _free_gb(cache_root) >= CACHE_MIN_FREE_GB:
            break
        log.info("evicting cache: %s", sub)
        shutil.rmtree(sub, ignore_errors=True)

    final_free = _free_gb(cache_root)
    if final_free < CACHE_MIN_FREE_GB:
        log.warning(
            "after eviction, free space still below threshold: "
            "%.1f GiB < %d GiB", final_free, CACHE_MIN_FREE_GB,
        )


def _free_gb(path: Path) -> float:
    """Free disk space in GiB on the filesystem hosting `path`."""
    usage = shutil.disk_usage(path)
    return usage.free / (1024 ** 3)


def _dir_size_bytes(path: Path) -> int:
    """Recursive sum of file sizes under `path`."""
    total = 0
    for p in path.rglob("*"):
        if p.is_file():
            try:
                total += p.stat().st_size
            except OSError:
                continue
    return total


def _compute_md5_sha1(path: Path, chunk_size: int = _HASH_CHUNK_SIZE) -> dict:
    """Compute MD5+SHA1 of a local file via streaming."""
    md5_h = hashlib.md5()
    sha1_h = hashlib.sha1()
    size = 0
    t0 = time.monotonic()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            md5_h.update(chunk)
            sha1_h.update(chunk)
            size += len(chunk)
    return {
        "size_bytes":       size,
        "md5":              md5_h.hexdigest(),
        "sha1":             sha1_h.hexdigest(),
        "duration_seconds": round(time.monotonic() - t0, 3),
    }


# ---------------------------------------------------------------------------
# Analyzer dispatch + result JSON construction
# ---------------------------------------------------------------------------

def _dispatch_analyzer(
    analyzer_name: str,
    dump_path: Path,
    summary: dict,
    preset: Optional[str],
    plugins: Optional[list[str]],
    cfg,
    on_progress: Optional[Callable[[str, int, int], None]] = None,
) -> dict:
    """Dispatch to the requested analyzer class and return its result dict.

    Stage E2.4 supported only "noop". Stage E3 adds "volatility" with
    the "fast" preset (5 Windows plugins). E4 will extend Vol3 with
    "full" + "custom" presets.

    `cfg` is needed by VolatilityAnalyzer to locate the XDG_CACHE_HOME
    directory (<cfg.work_dir>/vol3-cache) where Vol3 caches PDB
    symbol files between runs.

    `on_progress`, when provided, is forwarded to VolatilityAnalyzer
    as its ``on_plugin_start`` hook. The caller in _run_analysis
    builds a lambda that calls jobs.update_label() so the dashboard
    watch page shows live per-plugin progress instead of a frozen
    elapsed counter for the duration of a multi-minute full preset.
    The noop analyzer ignores the callback (it does not run plugins).
    """
    if analyzer_name == "noop":
        return NoOpAnalyzer().run(
            dump_path=dump_path,
            expected_md5=summary["dump_md5"],
            expected_sha1=summary["dump_sha1"],
        )
    if analyzer_name == "volatility":
        vol_cache = Path(cfg.work_dir) / "vol3-cache"
        return VolatilityAnalyzer(vol_cache_dir=vol_cache).run(
            dump_path=dump_path,
            expected_md5=summary["dump_md5"],
            expected_sha1=summary["dump_sha1"],
            summary=summary,
            preset=preset or "fast",
            plugins=plugins,
            on_plugin_start=on_progress,
        )
    raise ValueError(f"unknown analyzer: {analyzer_name!r}")


def _build_analysis_object_name(
    analyzer: str,
    preset: Optional[str],
    acquisition_id: str,
    job_id: str,
) -> str:
    """Compose the Swift object name for an analysis result.

    Pattern:
        analysis-<analyzer>[-<preset>]-<acquisition_id>-<UTC>-<job8>.json

    The preset is included only when set, so noop produces
    'analysis-noop-<acq>-<UTC>-<job8>.json' while a Vol3 fast preset
    will produce 'analysis-volatility-fast-<acq>-<UTC>-<job8>.json'.

    The trailing 8-char job_id prefix prevents collisions when two
    jobs land in the same UTC second (likely on a fast cache-hit
    pipeline). It also makes the object name traceable to its job
    record without a Swift metadata read.
    """
    parts = ["analysis", analyzer]
    if preset:
        parts.append(preset)
    parts.append(acquisition_id)
    parts.append(_utc_now_compact())
    parts.append(job_id[:8])
    return "-".join(parts) + ".json"


def _build_analysis_json(
    analysis_id: str,
    analyzer: str,
    analyzer_version: str,
    preset: Optional[str],
    plugins: Optional[list[str]],
    acquisition_id: str,
    operator: str,
    started_at: str,
    completed_at: str,
    summary: dict,
    analyzer_result: dict,
) -> bytes:
    """Build the serialized analysis JSON (schema v1.0).

    Layout mirrors the acquisition report v1.2: top-level metadata,
    nested `input_dump`, nested `coherence_check`, opaque `result`.

    The coherence_check block records all three independent hash
    measurements (acquisition, swift download, analyzer read) so the
    JSON is self-contained as evidence.
    """
    import json

    payload = {
        "schema_version":   ANALYSIS_SCHEMA_VERSION,
        "analysis_id":      analysis_id,
        "analyzer":         analyzer,
        "analyzer_version": analyzer_version,
        "preset":           preset,
        "plugins":          plugins,
        "acquisition_id":   acquisition_id,
        "operator":         operator,
        "timestamps": {
            "started_at":       started_at,
            "completed_at":     completed_at,
        },
        "input_dump": {
            "swift_object":  summary["dump_swift_object"],
            "size_bytes":    summary["dump_size_bytes"],
            "expected_md5":  summary["dump_md5"],
            "expected_sha1": summary["dump_sha1"],
        },
        "coherence_check": {
            "expected_md5":          summary["dump_md5"],
            "expected_sha1":         summary["dump_sha1"],
            "analyzer_read_md5":     analyzer_result.get("dump_md5"),
            "analyzer_read_sha1":    analyzer_result.get("dump_sha1"),
            "analyzer_size_bytes":   analyzer_result.get("dump_size_bytes"),
            "hashes_match_report":   analyzer_result.get("hashes_match_report"),
        },
        "result": analyzer_result,
    }
    return json.dumps(payload, indent=2, sort_keys=False).encode("utf-8")
# ============================================================================
# MISP ENRICHMENT — Stage F.2 Step F
# ----------------------------------------------------------------------------
# Parallel to _run_analysis() but structurally different: the input is
# another analysis JSON (not a RAM dump), and the witnessing chain is
# different (we validate the COHERENCE FLAG of the source analysis
# instead of recomputing hashes on a binary). Kept as a separate
# top-level pipeline so the existing dump-based code stays untouched.
# ============================================================================

def start_misp_enrichment_job(
    *,
    cfg,
    jobs: JobManager,
    job_id: str,
    input_analysis_id: str,
    operator: str,
) -> threading.Thread:
    """Spawn the worker thread for a MISP enrichment job and return it.

    Unlike start_analysis_job, the input is the Swift object name of an
    existing analysis-volatility-*.json (NOT an acquisition_id). The
    job record must already exist (created by the HTTP endpoint).
    """
    t = threading.Thread(
        target=_run_misp_enrichment,
        kwargs={
            "cfg":                cfg,
            "jobs":               jobs,
            "job_id":             job_id,
            "input_analysis_id":  input_analysis_id,
            "operator":           operator,
        },
        name=f"forensicnova-misp-{job_id[:8]}",
        daemon=True,
    )
    t.start()
    return t


def _run_misp_enrichment(
    cfg,
    jobs: JobManager,
    job_id: str,
    input_analysis_id: str,
    operator: str,
) -> None:
    """Full MISP enrichment pipeline, executed in a background thread.

    Pipeline (reuses PHASE_* constants from jobs.py with runtime
    labels adapted to the MISP flow):

      1. PHASE_DOWNLOADING_DUMP  — label: "Downloading source analysis
                                    JSON from Swift" (we reuse the
                                    swift.download_dump_with_hashes
                                    helper; the "dump" in its name is
                                    historical, it works for any object)
      2. PHASE_VERIFYING_HASH    — label: "Validating source analysis
                                    coherence" (we check that the
                                    input JSON itself reports
                                    hashes_match_report=True; we do NOT
                                    recompute hashes because we have
                                    no dump to recompute against)
      3. PHASE_RUNNING_ANALYZER  — label: "Running MISP enrichment"
      4. PHASE_UPLOADING_RESULTS — label: "Uploading analysis-misp JSON"
    """
    import configparser
    import json as _json

    log.info(
        "[job=%s] MISP enrichment worker started (input=%s)",
        job_id, input_analysis_id,
    )

    try:
        # ----- 1. PHASE: download source analysis from Swift ---------
        jobs.update_phase(
            job_id, PHASE_DOWNLOADING_DUMP,
            "Downloading source analysis JSON from Swift",
        )
        work_dir = Path(cfg.work_dir) / "misp-input" / job_id
        work_dir.mkdir(parents=True, exist_ok=True)
        input_local_path = work_dir / "source-analysis.json"

        def _dl_progress(label: str) -> None:
            jobs.update_label(job_id, label)

        # Reuse the existing Swift download primitive. It computes
        # md5/sha1 but we don't validate them against anything (the
        # source analysis JSON has its own internal integrity proofs
        # we check in step 2). The hashes are still useful for logs.
        downloaded = swift.download_dump_with_hashes(
            object_name=input_analysis_id,
            dest_path=input_local_path,
            cfg=cfg,
            progress_callback=_dl_progress,
        )
        log.info(
            "[job=%s] source analysis downloaded: %s (%d bytes, md5=%s)",
            job_id, input_local_path, downloaded["size_bytes"],
            downloaded["md5"][:8],
        )

        # ----- 2. PHASE: validate source coherence -------------------
        jobs.update_phase(
            job_id, PHASE_VERIFYING_HASH,
            "Validating source analysis coherence",
        )
        with input_local_path.open("r", encoding="utf-8") as fh:
            source_analysis = _json.load(fh)

        # Hard pre-check: the source analysis MUST be a Vol3 result
        # whose own coherence check passed. We refuse to enrich an
        # analysis whose dump integrity was already in doubt — that
        # would propagate uncertainty silently into the MISP output.
        # MispEnricher.run() re-checks this internally; doing it here
        # too gives a cleaner fail_job message and avoids loading the
        # MISP client when we already know we'd abort.
        if source_analysis.get("analyzer") != "volatility":
            raise ValueError(
                f"input_analysis_id {input_analysis_id!r} is not a "
                f"volatility analysis (analyzer="
                f"{source_analysis.get('analyzer')!r}); MISP enrichment "
                f"only accepts Vol3 outputs as input"
            )
        coh = source_analysis.get("coherence_check") or {}
        if not coh.get("hashes_match_report"):
            raise swift.IntegrityError(
                f"source analysis {input_analysis_id!r} failed its own "
                f"hash coherence check; refusing to enrich it"
            )
        os_hint = (source_analysis.get("result") or {}).get("os_hint")
        if os_hint != "windows":
            raise ValueError(
                f"source analysis has os_hint={os_hint!r}; MISP "
                f"enrichment is currently Windows-only"
            )
        acquisition_id = source_analysis.get("acquisition_id") or "unknown"

        # ----- 3. PHASE: run MISP enricher ---------------------------
        jobs.update_phase(
            job_id, PHASE_RUNNING_ANALYZER,
            "Running MISP enrichment",
        )

        # Lazy import to keep noop/volatility-only deployments from
        # paying the pymisp import cost. Same pattern as the swift
        # client import at the top of this module: heavy deps go in
        # the function body of the dispatcher that needs them.
        from forensicnova_analyzer.analyzers.misp import MispEnricher

        # Load MISP server config from /etc/forensicnova/misp.conf.
        # This file is owned by stack:stack with mode 0600 and was
        # provisioned by the DevStack plugin in Stage F.1. The path
        # is fixed by convention (not in cfg) because the analyzer
        # service runs as stack and reads the file directly.
        misp_conf_path = "/etc/forensicnova/misp.conf"
        misp_cfg = configparser.ConfigParser()
        if not misp_cfg.read(misp_conf_path):
            raise FileNotFoundError(
                f"MISP config not found at {misp_conf_path}; "
                f"was the F.1 plugin step skipped?"
            )
        msec = misp_cfg["misp"]
        enricher = MispEnricher(
            misp_url=msec["url"],
            auth_key=msec["auth_key"],
            verify_cert=msec.getboolean("verify_cert", fallback=False),
            timeout=msec.getint("timeout", fallback=30),
        )

        analysis_json_dict = enricher.run(
            input_analysis_json=source_analysis,
            operator=operator,
        )

        # ----- 4. PHASE: upload analysis-misp result -----------------
        jobs.update_phase(
            job_id, PHASE_UPLOADING_RESULTS,
            "Uploading analysis-misp JSON to Swift",
        )

        # MispEnricher.run() already computed the canonical analysis_id
        # (analysis-misp-<acq>-<UTC>-<job8>) and put it in the output
        # dict. Use it verbatim as the Swift object name so the
        # filename and the embedded id stay consistent.
        analysis_object_name = analysis_json_dict["analysis_id"] + ".json"

        json_bytes = _json.dumps(
            analysis_json_dict, indent=2, sort_keys=False,
        ).encode("utf-8")

        upload_metadata = {
            "analysis_id":         analysis_json_dict["analysis_id"],
            "analyzer":            "misp",
            "acquisition_id":      acquisition_id,
            "operator":            operator,
            "schema_version":      ANALYSIS_SCHEMA_VERSION,
            "input_analysis_id":   input_analysis_id,
        }
        upload_result = swift.upload_analysis_json(
            json_bytes=json_bytes,
            object_name=analysis_object_name,
            metadata=upload_metadata,
            cfg=cfg,
        )

        jobs.update_analysis_id(job_id, analysis_object_name)

        # ----- COMPLETED ---------------------------------------------
        summary = analysis_json_dict.get("summary") or {}
        jobs.complete_job(job_id, {
            "analysis_id":          analysis_object_name,
            "swift_object":         upload_result["swift_object"],
            "swift_etag":           upload_result["swift_etag"],
            "size_bytes":           upload_result["size_bytes"],
            "duration_seconds":     analysis_json_dict.get("duration_seconds"),
            "threat_score":         summary.get("threat_score"),
            "threat_score_reason":  summary.get("threat_score_reason"),
            "iocs_checked":         summary.get("total_iocs_checked"),
            "iocs_with_match":      summary.get("iocs_with_misp_match"),
        })
        log.info(
            "[job=%s] MISP DONE: analysis_id=%s score=%s size=%d",
            job_id, analysis_object_name,
            summary.get("threat_score"), upload_result["size_bytes"],
        )

    except swift.SwiftObjectNotFound as exc:
        log.error("[job=%s] swift object not found: %s", job_id, exc)
        jobs.fail_job(job_id, f"Swift object not found: {exc}")

    except swift.IntegrityError as exc:
        log.error("[job=%s] integrity failure: %s", job_id, exc)
        jobs.fail_job(job_id, f"Integrity verification failed: {exc}")

    except ValueError as exc:
        log.error("[job=%s] invalid input: %s", job_id, exc)
        jobs.fail_job(job_id, f"Invalid input: {exc}")

    except FileNotFoundError as exc:
        log.error("[job=%s] file not found: %s", job_id, exc)
        jobs.fail_job(job_id, f"File not found: {exc}")

    except (PermissionError, OSError) as exc:
        log.error("[job=%s] filesystem error: %s", job_id, exc)
        jobs.fail_job(job_id, f"Filesystem error: {exc}")

    except Exception as exc:  # noqa: BLE001
        log.exception("[job=%s] unexpected MISP enrichment error", job_id)
        jobs.fail_job(job_id, f"Internal error: {exc}")
