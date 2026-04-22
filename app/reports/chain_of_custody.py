"""ForensicNova — chain-of-custody event tracker.

A small, append-only event recorder used during the lifecycle of a single
acquisition.  Designed to be passed as a callback to all the lower-level
modules (hasher, acquirer, swift_client), so each step contributes its
events without coupling those modules to the reporter.

Persistence model:
  - Events are streamed to /var/log/forensicnova/chain-of-custody.jsonl
    in JSON Lines format (one JSON object per line, newline-terminated).
    JSONL is append-only and parsable line by line — no need to load the
    whole file into memory, ideal for an audit trail that grows over time.
  - Events are also kept in memory (self.events) so the final JSON report
    can embed the full event trail for the acquisition.
  - The CoC log file is intentionally separate from the application log
    (forensicnova.log): the application log is operational/diagnostic;
    the CoC log is forensic evidence and must remain clean and structured.

Usage:
    coc = ChainOfCustody(
        acquisition_id="abc-123",
        operator="dfir-tester",
        log_dir="/var/log/forensicnova",
    )
    coc.log_event("acquisition_initiated", {"instance_id": "..."})
    # ... pass coc.log_event as callback to hasher/acquirer/swift ...
    events = coc.events  # full list for the JSON report
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("forensicnova.reports.coc")

_COC_FILENAME = "chain-of-custody.jsonl"


class ChainOfCustody:
    """Per-acquisition chain-of-custody event recorder.

    Thread-safe: the JSONL writer is guarded by a lock so concurrent
    acquisitions (future thesis work) cannot interleave half-written lines.
    """

    def __init__(
        self,
        acquisition_id: str,
        operator: str,
        log_dir: str,
    ):
        self.acquisition_id = acquisition_id
        self.operator = operator
        self.log_dir = log_dir
        self.events: list[dict] = []
        self._lock = threading.Lock()
        self._jsonl_path = Path(log_dir) / _COC_FILENAME

        # Ensure log_dir exists (best-effort; the systemd unit runs as
        # the 'stack' user which already owns /var/log/forensicnova).
        try:
            os.makedirs(log_dir, exist_ok=True)
        except OSError as exc:
            log.warning("could not create CoC log dir %s: %s", log_dir, exc)

    def log_event(self, event_type: str, data: dict) -> None:
        """Record an event.

        :param event_type: short snake_case identifier (e.g. "hashing_started").
        :param data:       arbitrary JSON-serialisable dict with event payload.

        The event is enriched with acquisition_id, operator and an ISO-8601
        UTC timestamp before being persisted and added to the in-memory list.
        """
        event = {
            "acquisition_id": self.acquisition_id,
            "operator":       self.operator,
            "event_type":     event_type,
            "timestamp":      _utc_now_iso(),
            "data":           data,
        }

        with self._lock:
            self.events.append(event)
            try:
                with self._jsonl_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event, separators=(",", ":")) + "\n")
            except OSError as exc:
                log.error(
                    "failed to persist CoC event to %s: %s",
                    self._jsonl_path, exc,
                )
                # Do not raise — losing the disk persistence must not abort
                # the acquisition.  The in-memory copy is still in self.events
                # and will end up in the JSON report uploaded to Swift.

        log.info("CoC event recorded: %s (acq=%s)", event_type, self.acquisition_id)


def _utc_now_iso() -> str:
    """Return current UTC time as ISO-8601 string with 'Z' suffix.

    Format: 2026-04-22T14:23:45.123456Z (microsecond precision, UTC).
    Microsecond precision matters when multiple events happen in the same
    second (e.g. hashing_started and hashing_completed on small files).
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
