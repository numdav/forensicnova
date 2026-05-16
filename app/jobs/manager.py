"""ForensicNova — JobManager for async memory acquisition jobs.

State model:
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

    queued | dumping_memory | hashing | collecting_metadata
    | uploading_dump | uploading_report | finalizing
    | completed | failed

The 'label' field is what the dashboard displays. For SLO uploads, the
runner updates the label dynamically with "Uploading dump (segment X of Y)"
via update_label().

Recovery:
    recover_on_startup() scans the jobs directory at every service start
    and marks every job still in 'pending' or 'running' as 'failed' with
    a synthetic error message. An interrupted forensic acquisition is NOT
    resumable: a partial dump has no usable chain of custody, so we fail
    loudly and let the operator re-trigger from a known-clean state.

Filesystem layout assumption:
    The 'jobs_dir' is owned by the same user that runs the Flask service
    (stack on DevStack). The DevStack plugin.sh post-config phase creates
    /var/lib/forensicnova/jobs with mode 750 stack:stack.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("forensicnova.jobs.manager")

# Status values
STATUS_PENDING   = "pending"
STATUS_RUNNING   = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED    = "failed"

# Phase values
PHASE_QUEUED              = "queued"
PHASE_DUMPING             = "dumping_memory"
PHASE_HASHING             = "hashing"
PHASE_COLLECTING_METADATA = "collecting_metadata"
PHASE_UPLOADING_DUMP      = "uploading_dump"
PHASE_UPLOADING_REPORT    = "uploading_report"
PHASE_FINALIZING          = "finalizing"
PHASE_COMPLETED           = "completed"
PHASE_FAILED              = "failed"

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
    """Thread-safe, filesystem-persisted job state store."""

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
        instance_id: str,
        instance_name: Optional[str] = None,
    ) -> dict:
        """Create a new job record in PENDING/QUEUED state."""
        now = _utc_now_iso()
        data = {
            "job_id":          job_id,
            "acquisition_id":  None,  # set by runner once it generates one
            "instance_id":     instance_id,
            "instance_name":   instance_name,
            "operator":        operator,
            "status":          STATUS_PENDING,
            "phase":           PHASE_QUEUED,
            "label":           "Queued, waiting for acquisition slot",
            "started_at":      now,
            "completed_at":    None,
            "elapsed_seconds": 0,
            "error_message":   None,
            "result":          None,
        }
        self._write(job_id, data)
        log.info("[job=%s] created (operator=%s, instance=%s)",
                 job_id, operator, instance_id)
        return data

    def update_acquisition_id(self, job_id: str, acquisition_id: str) -> None:
        with self._lock_for(job_id):
            data = self._read(job_id)
            if data is None:
                return
            data["acquisition_id"] = acquisition_id
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
        """Update only the label (used for fine-grained progress, e.g. SLO segments)."""
        with self._lock_for(job_id):
            data = self._read(job_id)
            if data is None:
                return
            data["label"] = label
            data["elapsed_seconds"] = _elapsed(data.get("started_at"))
            self._write(job_id, data)
            log.debug("[job=%s] label=%r", job_id, label)

    def complete_job(self, job_id: str, result: dict) -> None:
        """Mark a job as COMPLETED and attach the final acquisition result."""
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
        """List all jobs, most recent first (by started_at)."""
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
        """Mark any pending or running job as failed.

        Called once at application startup. An acquisition that was
        in-flight when the service was restarted has, by definition, no
        valid chain of custody and must NOT be marked completed nor
        resumed: a partial dump cannot be trusted as evidence.
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
                    "Service was restarted before this acquisition completed. "
                    "Partial dumps cannot be trusted as forensic evidence; "
                    "re-trigger the acquisition from a known-clean state."
                )
                self._write(data.get("job_id") or p.stem, data)
                recovered += 1
        if recovered:
            log.info("recover_on_startup: marked %d orphan job(s) as failed", recovered)
        return recovered

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
