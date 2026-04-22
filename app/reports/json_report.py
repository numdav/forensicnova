"""ForensicNova — JSON forensic report builder.

Stateless module that assembles the final machine-readable report for an
acquisition.  The report is the canonical document that:
  - travels with the dump as a separate Swift object
  - is consumed by downstream tools (Volatility, Autopsy, custom scripts)
  - is the source of truth verified against the dump's hash on the SIFT
    workstation after download

Schema (frozen for FASE 4; extended in FASE 5+ for IOC/YARA results):
  {
    "schema_version":   "1.0",
    "acquisition_id":   "uuid",
    "timestamp":        "ISO-8601 UTC",
    "operator":         "dfir-tester",
    "tool":             {"name": "ForensicNova", "version": "0.1.0"},
    "instance": {
        "id":     "nova-uuid",
        "name":   "vm-name",
        "domain": "instance-0000001a"
    },
    "dump": {
        "size_bytes":  4294967296,
        "md5":         "...",
        "sha1":        "...",
        "swift_object": "forensics/dump-<uuid>.raw",
        "swift_etag":  "...",
        "etag_verified": true,
        "format":      "raw",
        "acquisition_method": "libvirt-coreDumpWithFormat"
    },
    "chain_of_custody": [ ...events from ChainOfCustody.events... ]
  }

This module does not perform I/O — it returns the dict and the JSON-encoded
bytes; uploading to Swift is the caller's responsibility (api/v1.py uses
swift_client.upload_json()).
"""
from __future__ import annotations

import json
import logging
from typing import Optional

log = logging.getLogger("forensicnova.reports.json")

SCHEMA_VERSION = "1.0"


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
    events: Optional[list[dict]] = None,
    acquisition_method: str = "libvirt-coreDumpWithFormat",
) -> dict:
    """Assemble the structured forensic report.

    :param acquisition_id: Unique acquisition UUID.
    :param operator:       Username from the Keystone token (dfir-tester).
    :param instance_id:    Nova instance UUID.
    :param instance_name:  Human-readable VM name from Nova.
    :param domain_name:    libvirt domain name (e.g. "instance-0000001a").
    :param hash_result:    Output of hasher.compute_hashes().
    :param swift_result:   Output of swift_client.upload_dump().
    :param tool_version:   ForensicNova version string (app.__version__).
    :param timestamp:      ISO-8601 timestamp of acquisition completion.
    :param events:         Optional list of CoC events (ChainOfCustody.events).
    :param acquisition_method: Acquisition technique used; defaults to the
                               libvirt API call name for traceability.

    :returns: dict matching the SCHEMA_VERSION 1.0 schema.
    """
    report = {
        "schema_version": SCHEMA_VERSION,
        "acquisition_id": acquisition_id,
        "timestamp":      timestamp,
        "operator":       operator,
        "tool": {
            "name":    "ForensicNova",
            "version": tool_version,
        },
        "instance": {
            "id":     instance_id,
            "name":   instance_name,
            "domain": domain_name,
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
        "chain_of_custody": events or [],
    }

    log.info(
        "report generated: acq=%s, instance=%s, dump=%s, events=%d",
        acquisition_id, instance_id,
        swift_result.get("swift_object"), len(report["chain_of_custody"]),
    )
    return report


def serialize_report(report: dict) -> bytes:
    """Encode a report dict to UTF-8 JSON bytes ready for Swift upload.

    Uses indent=2 for human readability — the report is meant to be
    inspected by analysts, not just machines.  Size cost is negligible
    (a few KB) compared to the dump it accompanies.
    """
    return json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
