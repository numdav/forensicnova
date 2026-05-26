"""ForensicNova Analyzer — JobManager for async memory analysis jobs.

State model (identical pattern to app/jobs/manager.py):
  - One JSON file per job: <jobs_dir>/<job_id>.json
  - Atomic writes via tempfile + os.rename (POSIX guarantees atomicity
    when source and destination live on the same filesystem).
  - Per-job RLock to serialize concurrent updates within a single worker.
  - Manager-level RLock to protect the lock-dictionary itself against
    races on first-touch creation.

Lifecycle:
    pending  -> running  -> completed
    pending  -> running  -> failed
    pending  ->            failed   (rare, e.g. thread spawn fails)

Status is the macro state used by the UI for filtering and color coding.
Phase is the in-flight pipeline step (independent of status while running):

    queued | downloading_dump | verifying_hash | running_analyzer
    | uploading_results | completed | failed

The 'label' field is what the dashboard displays. For analyzers that
expose progress (e.g. Volatility plugin-by-plugin in Stage E3+), the
runner updates the label dynamically with "Running plugin X (3 of 8)"
via update_label().

Recovery:
    recover_on_startup() scans the jobs directory at every service start
    and marks every job still in 'pending' or 'running' as 'failed' with
    a synthetic error message. An interrupted analysis is NOT resumed:
    partial Volatility output has no chain-of-custody value, and the
    runner is idempotent on the input dump anyway, so the operator can
    safely re-trigger from scratch.

Why a duplicate of app/jobs/manager.py instead of a shared library:
    Acquisition backend (app/) and analyzer backend (this) are
    independently-deployed services with separate venvs, separate
    systemd units, and independent release cycles. A shared library
    would re-introduce the cross-service coupling we explicitly avoid.
    The duplication is scoped: the lock/atomic-write/recovery
    infrastructure is identical, only the PHASE_* constants and
    create_job() schema differ.

Filesystem layout assumption:
    The 'jobs_dir' is owned by the same user that runs the Flask
    analyzer service (stack on DevStack). The DevStack plugin.sh
    post-config phase creates /var/lib/forensicnova-analyzer/jobs with
    mode 750 stack:stack.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("forensicnova_analyzer.jobs")

# ---------------------------------------------------------------------------
# Status values — same vocabulary as the acquisition backend so the
# dashboard can color-code both services with one set of CSS classes.
# ---------------------------------------------------------------------------
STATUS_PENDING   = "pending"
STATUS_RUNNING   = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED    = "failed"

# ---------------------------------------------------------------------------
# Phase values — analyzer-specific pipeline. Five operational phases
# plus the two terminal sentinels (completed / failed). The terminal
# phases coincide with the matching status: redundant on purpose, lets
# UIs filter by phase or status interchangeably.
# ---------------------------------------------------------------------------
PHASE_QUEUED             = "queued"
PHASE_DOWNLOADING_DUMP   = "downloading_dump"
PHASE_VERIFYING_HASH     = "verifying_hash"
PHASE_RUNNING_ANALYZER   = "running_analyzer"
PHASE_UPLOADING_RESULTS  = "uploading_results"
PHASE_COMPLETED          = "completed"
PHASE_FAILED             = "failed"

TERMINAL_STATUSES = {STATUS_COMPLETED, STATUS_FAILED}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _elapsed(started_at: Optional[str]) -> int:
    """Compute integer seconds since started_at (ISO 8601 with .%fZ)."""
    if not started_at:
        return 0
    try:
        # Tolerant parse: strip the trailing 'Z' and let fromisoformat handle it.
        s = started_at.rstrip("Z")
        start = datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - start
        return int(delta.total_seconds())
    except (ValueError, TypeError):
        return 0


class JobManager:
    """Thread-safe, filesystem-persisted analyzer job state store."""

    def __init__(self, jobs_dir: Path | str):
        self.jobs_dir = Path(jobs_dir)
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        # Per-job locks live in this dict; the dict itself is protected
        # by self._dict_lock to avoid races on first access.
        self._locks: dict[str, threading.RLock] = {}
        self._dict_lock = threading.RLock()

    # ------------------------------------------------------------------
    # Public API — writes
    # ------------------------------------------------------------------

    def create_job(
        self,
        job_id: str,
        operator: str,
        acquisition_id: str,
        analyzer: str,
        preset: Optional[str] = None,
        plugins: Optional[list[str]] = None,
    ) -> dict:
        """Create a new analysis job record in PENDING/QUEUED state.

        :param job_id:         caller-generated UUID for the job
        :param operator:       human or service account name driving
                               this analysis (recorded for audit only;
                               authorization is handled in the HTTP layer)
        :param acquisition_id: UUID of the acquisition (in Swift) to analyze
        :param analyzer:       analyzer name, e.g. "noop", "volatility"
        :param preset:         optional preset, e.g. "fast" / "full" /
                               "custom" — only meaningful for volatility
        :param plugins:        optional explicit plugin list (only used
                               when preset="custom")

        :returns: the newly persisted job record (identical to what
                  get_job() would return).
        """
        now = _utc_now_iso()
        data = {
            "job_id":          job_id,
            "acquisition_id":  acquisition_id,
            "analyzer":        analyzer,
            "preset":          preset,
            "plugins":         plugins,
            "analysis_id":     None,    # set by runner once Swift PUT lands
            "operator":        operator,
            "status":          STATUS_PENDING,
            "phase":           PHASE_QUEUED,
            "label":           "Queued, waiting for analyzer slot",
            "started_at":      now,
            "completed_at":    None,
            "elapsed_seconds": 0,
            "error_message":   None,
            "result":          None,
        }
        self._write(job_id, data)
        log.info(
            "[job=%s] created (operator=%s, acquisition=%s, analyzer=%s, "
            "preset=%s, plugins=%s)",
            job_id, operator, acquisition_id, analyzer, preset, plugins,
        )
        return data

    def update_analysis_id(self, job_id: str, analysis_id: str) -> None:
        """Attach the analysis_id (object name in Swift) once known.

        Symmetric to update_acquisition_id() in the acquisition backend.
        The analyzer runner sets this after the analysis-*.json upload
        succeeds; the dashboard then uses it to deep-link to the result.
        """
        with self._lock_for(job_id):
            data = self._read(job_id)
            if data is None:
                return
            data["analysis_id"] = analysis_id
            self._write(job_id, data)

    def update_phase(
        self,
        job_id: str,
        phase: str,
        label: Optional[str] = None,
    ) -> None:
        """Transition the in-flight phase; flips status to RUNNING on first move."""
        with self._lock_for(job_id):
            data = self._read(job_id)
            if data is None:
                return
            data["phase"] = phase
            if label is not None:
                data["label"] = label
            data["elapsed_seconds"] = _elapsed(data.get("started_at"))
            # First transition out of 'queued' flips status pending -> running.
            if data.get("status") == STATUS_PENDING and phase != PHASE_QUEUED:
                data["status"] = STATUS_RUNNING
            self._write(job_id, data)
            log.info("[job=%s] phase=%s label=%r", job_id, phase, data["label"])

    def update_label(self, job_id: str, label: str) -> None:
        """Update only the label (fine-grained progress, e.g. Vol3 per-plugin)."""
        with self._lock_for(job_id):
            data = self._read(job_id)
            if data is None:
                return
            data["label"] = label
            data["elapsed_seconds"] = _elapsed(data.get("started_at"))
            self._write(job_id, data)
            log.debug("[job=%s] label=%r", job_id, label)

    def complete_job(self, job_id: str, result: dict) -> None:
        """Mark a job as COMPLETED and attach the final analysis result."""
        with self._lock_for(job_id):
            data = self._read(job_id)
            if data is None:
                return
            data["status"]          = STATUS_COMPLETED
            data["phase"]           = PHASE_COMPLETED
            data["label"]           = "Completed"
            data["completed_at"]    = _utc_now_iso()
            data["elapsed_seconds"] = _elapsed(data.get("started_at"))
            data["result"]          = result
            self._write(job_id, data)
            log.info("[job=%s] COMPLETED (elapsed=%ds)",
                     job_id, data["elapsed_seconds"])

    def fail_job(self, job_id: str, error_message: str) -> None:
        """Mark a job as FAILED with a human-readable error message."""
        with self._lock_for(job_id):
            data = self._read(job_id)
            if data is None:
                return
            data["status"]          = STATUS_FAILED
            data["phase"]           = PHASE_FAILED
            data["label"]           = "Failed"
            data["completed_at"]    = _utc_now_iso()
            data["elapsed_seconds"] = _elapsed(data.get("started_at"))
            data["error_message"]   = error_message
            self._write(job_id, data)
            log.warning("[job=%s] FAILED: %s", job_id, error_message)

    # ------------------------------------------------------------------
    # Public API — reads
    # ------------------------------------------------------------------

    def get_job(self, job_id: str) -> Optional[dict]:
        """Read a job's current state; returns None if not found."""
        return self._read(job_id)

    def list_jobs(self) -> list[dict]:
        """List all analyzer jobs, most recent first (by started_at)."""
        jobs: list[dict] = []
        for p in self.jobs_dir.glob("*.json"):
            try:
                with p.open("r", encoding="utf-8") as fh:
                    jobs.append(json.load(fh))
            except (OSError, ValueError) as exc:
                log.warning("could not read job file %s: %s", p, exc)
                continue
        jobs.sort(key=lambda j: j.get("started_at") or "", reverse=True)
        return jobs

    # ------------------------------------------------------------------
    # Recovery
    # ------------------------------------------------------------------

    def recover_on_startup(self) -> int:
        """Mark any pending or running analyzer job as failed.

        Called once at application startup. An analysis that was
        in-flight when the service restarted may have left:
          - a partial dump in the working directory (eats disk)
          - a partial result not yet uploaded to Swift
          - or nothing at all (failed right after dispatch)

        We do NOT resume: re-triggering an analysis on the same
        acquisition_id is idempotent and cheap, but determining the
        exact restart point would require tracking each phase's
        sub-progress on disk — out of scope for this scaffolding.
        Instead the runner is expected to clean up its own working
        directory at start; a startup sweep simply lets the dashboard
        show the truth ("failed due to restart").
        """
        recovered = 0
        for p in self.jobs_dir.glob("*.json"):
            try:
                with p.open("r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, ValueError) as exc:
                log.warning("recover_on_startup: could not read %s: %s", p, exc)
                continue
            if data.get("status") in {STATUS_PENDING, STATUS_RUNNING}:
                data["status"]          = STATUS_FAILED
                data["phase"]           = PHASE_FAILED
                data["label"]           = "Failed: interrupted by service restart"
                data["completed_at"]    = _utc_now_iso()
                data["elapsed_seconds"] = _elapsed(data.get("started_at"))
                data["error_message"]   = (
                    "Analyzer service was restarted before this analysis "
                    "completed. Partial analyses cannot be trusted as "
                    "forensic evidence; please re-trigger the analysis "
                    "from a known-clean state."
                )
                self._write(data.get("job_id") or p.stem, data)
                recovered += 1
        if recovered:
            log.info(
                "recover_on_startup: marked %d orphan analyzer job(s) as failed",
                recovered,
            )
        return recovered

    # ------------------------------------------------------------------
    # Deletion (manual cleanup)
    # ------------------------------------------------------------------

    def delete_job(self, job_id: str) -> dict:
        """Remove a job's persisted record from disk.

        Idempotent: if the job file does not exist the function returns
        a 'no-op' result and does not raise. Returns the previous job
        record (with at minimum the analysis_id so the caller can decide
        whether to cascade-delete the Swift analysis object), or a
        skeleton dict when the file was absent.

        Concurrency: takes the per-job lock so a delete cannot race
        against an in-flight write (atomic-rename in _write). The lock
        entry stays in self._locks after deletion to avoid free-then-
        re-create races; the memory cost is one RLock per ever-seen
        job_id, negligible for the expected single-VM workload.

        Why this is a manager-level method and not a thin os.unlink
        wrapper: the dashboard's Delete action needs to also drop the
        matching analysis JSON from Swift (if any). Returning the full
        previous record lets the caller (API endpoint) decide whether
        to cascade, without re-reading the file.
        """
        with self._lock_for(job_id):
            data = self._read(job_id)
            p = self._path(job_id)
            if data is None and not p.exists():
                log.info("[job=%s] delete: nothing to remove (already gone)",
                         job_id)
                return {
                    "job_id":      job_id,
                    "deleted":     False,
                    "analysis_id": None,
                }
            try:
                if p.exists():
                    os.unlink(str(p))
            except OSError as exc:
                log.warning("[job=%s] delete: unlink failed: %s", job_id, exc)
                return {
                    "job_id":      job_id,
                    "deleted":     False,
                    "analysis_id": (data or {}).get("analysis_id"),
                    "error":       str(exc),
                }
            log.info("[job=%s] DELETED (had analysis_id=%s)",
                     job_id, (data or {}).get("analysis_id"))
            return {
                "job_id":      job_id,
                "deleted":     True,
                "analysis_id": (data or {}).get("analysis_id"),
            }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _lock_for(self, job_id: str) -> threading.RLock:
        """Return the per-job RLock, creating it on first access."""
        with self._dict_lock:
            lock = self._locks.get(job_id)
            if lock is None:
                lock = threading.RLock()
                self._locks[job_id] = lock
            return lock

    def _path(self, job_id: str) -> Path:
        return self.jobs_dir / f"{job_id}.json"

    def _read(self, job_id: str) -> Optional[dict]:
        p = self._path(job_id)
        if not p.exists():
            return None
        try:
            with p.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError) as exc:
            log.warning("could not read job %s: %s", job_id, exc)
            return None

    def _write(self, job_id: str, data: dict) -> None:
        """Atomic write: tempfile in same dir, then os.rename."""
        p = self._path(job_id)
        tmp_fd, tmp_path = tempfile.mkstemp(
            dir=str(self.jobs_dir),
            prefix=f".{job_id}.",
            suffix=".tmp",
            text=False,
        )
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as tmp_fh:
                json.dump(data, tmp_fh, indent=2)
                tmp_fh.flush()
                os.fsync(tmp_fh.fileno())
            os.rename(tmp_path, str(p))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
