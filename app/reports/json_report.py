"""ForensicNova — JSON forensic report builder.

Produces the machine-readable report that travels with the dump as a
second Swift object and that the SIFT workstation consumes for
hash verification and analysis routing.

Schema v1.1 (FASE 4 final):

  {
    "schema_version": "1.1",
    "acquisition_id": "uuid",
    "operator":       "dfir-tester",
    "tool":           {"name": "ForensicNova", "version": "0.1.0"},

    "timestamps": {
        "started_at":       "ISO-8601 UTC",
        "completed_at":     "ISO-8601 UTC",
        "duration_seconds": 7.12
    },

    "instance": {"id": "...", "name": "...", "domain": "instance-xxxx"},

    "target_system": {
        "nova":       {...},
        "flavor":     {...},
        "glance":     {...},
        "hypervisor": {"type": "kvm"},
        "libvirt":    {...}
    },

    "dump": {
        "size_bytes": ..., "md5": "...", "sha1": "...",
        "swift_object": "forensics/dump-<vm>-<ts>.raw",
        "swift_etag": "...",
        "etag_verified": true,
        "format": "raw", "acquisition_method": "libvirt-coreDumpWithFormat"
    },

    "report": {
        "swift_object": "forensics/report-<vm>-<ts>.json",
        "filename":     "report-<vm>-<ts>.json"
    },

    "chain_of_custody": {
        "total_events": 11,
        "events": [{"seq": 1, "event_type": "...", "description": "...",
                    "timestamp": "...", "data": {...}}, ...]
    }
  }
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

log = logging.getLogger("forensicnova.reports.json")

SCHEMA_VERSION = "1.1"

_EVENT_DESCRIPTIONS = {
    "api_request_received":           "REST endpoint received the acquisition request",
    "acquisition_initiated":          "Acquisition pipeline started — instance identified",
    "domain_lookup_completed":        "Nova UUID resolved to libvirt domain",
    "memory_dump_started":            "Memory acquisition started — libvirt coreDumpWithFormat invoked",
    "memory_dump_completed":          "Raw memory dump written to hypervisor staging area",
    "dump_ownership_fixed":           "Dump file chowned to service user for pipeline access",
    "hashing_started":                "MD5 + SHA-1 streaming hash started",
    "hashing_completed":              "Hashes computed (single-pass, 64 KB chunks)",
    "swift_upload_started":           "Upload of dump to Swift 'forensics' container started",
    "swift_upload_verified":          "Swift ETag matches local MD5 — integrity confirmed",
    "swift_upload_integrity_failure": "Swift ETag MISMATCH — local dump preserved for debug",
    "swift_report_uploaded":          "JSON report uploaded to Swift as second object",
    "local_dump_secure_deleted":      "Local dump shred-overwritten and unlinked",
    "local_dump_preserved":           "Local dump intentionally NOT deleted (integrity failure)",
    "acquisition_failed":             "Acquisition pipeline aborted — see data.reason",
}


def generate_report(
    acquisition_id: str,
    operator: str,
    instance_id: str,
    instance_name: str,
    domain_name: str,
    hash_result: dict,
    swift_result: dict,
    tool_version: str,
    timestamp: str,
    started_at: Optional[str] = None,
    target_system: Optional[dict] = None,
    report_object_name: Optional[str] = None,
    container: str = "forensics",
    events: Optional[list[dict]] = None,
    acquisition_method: str = "libvirt-coreDumpWithFormat",
) -> dict:
    """Assemble the structured forensic report (schema v1.1).

    :param report_object_name: The Swift object name under which this report
                               will be uploaded (e.g. 'report-vm-ts.json').
                               Embedded in the report itself for self-reference
                               so analysts can cross-reference dump ↔ report.
    :param container:          Swift container (default 'forensics').
    """
    duration = _compute_duration(started_at, timestamp)
    coc_events = _enrich_events(events or [])

    report_block = _build_report_block(report_object_name, container)

    report = {
        "schema_version": SCHEMA_VERSION,
        "acquisition_id": acquisition_id,
        "operator":       operator,
        "tool": {
            "name":    "ForensicNova",
            "version": tool_version,
        },
        "timestamps": {
            "started_at":       started_at or timestamp,
            "completed_at":     timestamp,
            "duration_seconds": duration,
        },
        "instance": {
            "id":     instance_id,
            "name":   instance_name,
            "domain": domain_name,
        },
        "target_system": target_system or {
            "nova":       {},
            "flavor":     {},
            "glance":     {},
            "hypervisor": {},
            "libvirt":    {"domain_name": domain_name},
        },
        "dump": {
            "size_bytes":         hash_result.get("size_bytes"),
            "md5":                hash_result.get("md5"),
            "sha1":               hash_result.get("sha1"),
            "swift_object":       swift_result.get("swift_object"),
            "swift_etag":         swift_result.get("swift_etag"),
            "etag_verified":      swift_result.get("etag_verified"),
            "format":             "raw",
            "acquisition_method": acquisition_method,
        },
        "report": report_block,
        "chain_of_custody": {
            "total_events": len(coc_events),
            "events":       coc_events,
        },
    }

    log.info(
        "report generated: acq=%s, instance=%s, dump=%s, report=%s, events=%d",
        acquisition_id, instance_id,
        swift_result.get("swift_object"), report_block.get("swift_object"),
        len(coc_events),
    )
    return report


def serialize_report(report: dict) -> bytes:
    """Encode a report dict to UTF-8 JSON bytes ready for Swift upload."""
    import json
    return json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_report_block(report_object_name: Optional[str], container: str) -> dict:
    """Self-reference block so the report knows its own Swift coordinates."""
    if not report_object_name:
        return {"swift_object": None, "filename": None}
    return {
        "swift_object": f"{container}/{report_object_name}",
        "filename":     report_object_name,
    }


def _enrich_events(events: list[dict]) -> list[dict]:
    """Add 1-based seq and human-readable description to each CoC event."""
    enriched = []
    for i, ev in enumerate(events, start=1):
        ev_type = ev.get("event_type", "unknown")
        enriched.append({
            "seq":         i,
            "event_type":  ev_type,
            "description": _EVENT_DESCRIPTIONS.get(
                ev_type, "(no description registered for this event type)"
            ),
            "timestamp":   ev.get("timestamp"),
            "data":        ev.get("data", {}),
        })
    return enriched


def _compute_duration(started_at: Optional[str], completed_at: str) -> Optional[float]:
    """Parse two ISO-8601 UTC strings and return duration in seconds."""
    if not started_at:
        return None
    try:
        start = _parse_iso_utc(started_at)
        end   = _parse_iso_utc(completed_at)
        return round((end - start).total_seconds(), 3)
    except Exception as exc:  # noqa: BLE001
        log.debug("duration parsing failed (%s -> %s): %s",
                  started_at, completed_at, exc)
        return None


def _parse_iso_utc(s: str) -> datetime:
    """Parse 'YYYY-MM-DDTHH:MM:SS.ffffffZ' into a datetime."""
    normalised = s.replace("Z", "+00:00")
    return datetime.fromisoformat(normalised)
