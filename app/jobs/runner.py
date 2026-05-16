"""ForensicNova — async acquisition runner.

Spawns a daemon thread that runs the full memory-acquisition pipeline
that v1.memory_acquire used to run synchronously, calling
JobManager.update_phase()/update_label() at every pipeline transition so
the dashboard (and any API client polling /jobs/<id>) can show
"where we are now".

Pipeline ordering (preserved from the synchronous version):
    1.  pre-flight CoC bootstrap                  -> phase: queued
    2.  acquire_memory()                           -> phase: dumping_memory
    3.  _lookup_domain_name()                      -> (no phase change)
    4.  compute_hashes()                           -> phase: hashing
    5.  nova_metadata.collect()                    -> phase: collecting_metadata
    6.  upload_dump() (single-PUT or SLO)           -> phase: uploading_dump
            SLO progress: "Uploading dump (segment X of Y)"
    7.  secure_delete()                            -> phase: finalizing
    8.  generate_report() + upload_json()          -> phase: uploading_report
    9.  finalize -> jobs.complete_job(result)       -> phase: completed

Concurrency:
    A module-level threading.Lock serialises acquisitions: at most one
    worker thread runs the libvirt coreDumpWithFormat() path at a time.
    Other workers wait in 'queued' until the lock is free. This avoids
    QEMU/libvirt concurrency issues on a single hypervisor.

Errors at any step:
    - the per-error coc.log_event is preserved (chain of custody integrity)
    - jobs.fail_job(error_message) is called with a short error string
    - the local dump is preserved on integrity failure (existing behaviour
      inherited from app.api.v1.memory_acquire)
"""
from __future__ import annotations

import logging
import threading
import uuid

import libvirt

from app.forensics import nova_metadata
from app.forensics.acquirer import acquire_memory, secure_delete
from app.hashing.hasher import compute_hashes
from app.reports.chain_of_custody import ChainOfCustody
from app.reports.json_report import generate_report, serialize_report
from app.storage.swift_client import IntegrityError, upload_dump, upload_json

# Reuse the helpers already defined in the v1 API module so we don't
# duplicate logic. These are package-internal (underscore prefix) but
# importable; the alternative — extracting them into a separate helper
# module — would force unrelated changes to api/v1.py imports.
from app.api.v1 import (
    _lookup_domain_name,
    _sanitize_vm_name,
    _utc_now_compact,
    _utc_now_iso,
)
from app.jobs.manager import (
    JobManager,
    PHASE_COLLECTING_METADATA,
    PHASE_DUMPING,
    PHASE_FINALIZING,
    PHASE_HASHING,
    PHASE_UPLOADING_DUMP,
    PHASE_UPLOADING_REPORT,
)

log = logging.getLogger("forensicnova.jobs.runner")

# Module-level: at most one concurrent acquisition. libvirt's
# coreDumpWithFormat briefly pauses QEMU; running it concurrently on the
# same hypervisor invites trouble. Other workers wait in 'queued' state
# until this lock is free.
_acquisition_lock = threading.Lock()


def start_acquisition_job(
    *,
    cfg,
    tool_version: str,
    jobs: JobManager,
    job_id: str,
    instance_id: str,
    operator: str,
) -> threading.Thread:
    """Spawn the worker thread and return it (daemon=True)."""
    t = threading.Thread(
        target=_run_acquisition,
        kwargs={
            "cfg":          cfg,
            "tool_version": tool_version,
            "jobs":         jobs,
            "job_id":       job_id,
            "instance_id":  instance_id,
            "operator":     operator,
        },
        name=f"forensicnova-job-{job_id[:8]}",
        daemon=True,
    )
    t.start()
    return t


def _run_acquisition(
    cfg,
    tool_version: str,
    jobs: JobManager,
    job_id: str,
    instance_id: str,
    operator: str,
) -> None:
    """Full acquisition pipeline, executed in a background daemon thread."""
    log.info(
        "[job=%s] worker thread started; waiting for acquisition lock",
        job_id,
    )

    with _acquisition_lock:
        log.info("[job=%s] acquisition lock acquired", job_id)

        acquisition_id = str(uuid.uuid4())
        jobs.update_acquisition_id(job_id, acquisition_id)

        started_at        = _utc_now_iso()
        timestamp_compact = _utc_now_compact()

        coc = ChainOfCustody(
            acquisition_id=acquisition_id,
            operator=operator,
            log_dir=cfg.log_dir,
        )
        coc.log_event("async_job_started", {
            "job_id":      job_id,
            "instance_id": instance_id,
        })

        try:
            # ----- PHASE: dumping_memory -----
            jobs.update_phase(
                job_id, PHASE_DUMPING,
                "Dumping VM memory at hypervisor level",
            )
            dump_path = acquire_memory(
                instance_id=instance_id,
                acquisition_id=acquisition_id,
                work_dir=cfg.work_dir,
                libvirt_uri=cfg.libvirt_uri,
                log_event=coc.log_event,
            )
            domain_name = _lookup_domain_name(cfg.libvirt_uri, instance_id)

            # ----- PHASE: hashing -----
            jobs.update_phase(
                job_id, PHASE_HASHING,
                "Computing MD5 + SHA1 hashes (streaming)",
            )
            hash_result = compute_hashes(dump_path, log_event=coc.log_event)

            # ----- PHASE: collecting_metadata -----
            jobs.update_phase(
                job_id, PHASE_COLLECTING_METADATA,
                "Collecting Nova / Glance / libvirt metadata",
            )
            target_system = nova_metadata.collect(
                instance_id=instance_id,
                domain_name=domain_name,
                libvirt_uri=cfg.libvirt_uri,
                cfg=cfg,
            )

            vm_name_raw = (
                (target_system.get("nova") or {}).get("name")
                or domain_name
                or "unknown"
            )
            vm_name_safe = _sanitize_vm_name(vm_name_raw)

            swift_object_name  = f"dump-{vm_name_safe}-{timestamp_compact}.raw"
            report_object_name = f"report-{vm_name_safe}-{timestamp_compact}.json"

            swift_metadata = {
                "acquisition_id": acquisition_id,
                "operator":       operator,
                "instance_id":    instance_id,
                "instance_name":  vm_name_raw,
                "domain_name":    domain_name,
                "md5":            hash_result["md5"],
                "sha1":           hash_result["sha1"],
                "tool_version":   tool_version,
                "timestamp":      _utc_now_iso(),
            }

            # ----- PHASE: uploading_dump -----
            jobs.update_phase(
                job_id, PHASE_UPLOADING_DUMP,
                f"Uploading dump to Swift (target: {vm_name_raw})",
            )

            def _progress(label: str) -> None:
                """Per-segment progress callback for SLO uploads."""
                jobs.update_label(job_id, label)

            swift_result = upload_dump(
                local_path=dump_path,
                object_name=swift_object_name,
                metadata=swift_metadata,
                cfg=cfg,
                log_event=coc.log_event,
                progress_callback=_progress,
            )

            # ----- PHASE: finalizing -----
            jobs.update_phase(
                job_id, PHASE_FINALIZING,
                "Verifying integrity and cleaning up local staging",
            )
            if swift_result["etag_verified"]:
                secure_delete(dump_path)
                coc.log_event("local_dump_secure_deleted", {
                    "path": str(dump_path),
                })
            else:
                log.warning(
                    "[job=%s] etag NOT verified — local dump preserved at %s",
                    job_id, dump_path,
                )
                coc.log_event("local_dump_preserved", {
                    "path":   str(dump_path),
                    "reason": "etag_not_verified",
                })

            completed_at = _utc_now_iso()
            report = generate_report(
                acquisition_id=acquisition_id,
                operator=operator,
                instance_id=instance_id,
                instance_name=vm_name_raw,
                domain_name=domain_name,
                hash_result=hash_result,
                swift_result=swift_result,
                tool_version=tool_version,
                timestamp=completed_at,
                started_at=started_at,
                target_system=target_system,
                report_object_name=report_object_name,
                container=cfg.swift_container,
                events=list(coc.events),
            )
            report_bytes = serialize_report(report)

            # ----- PHASE: uploading_report -----
            jobs.update_phase(
                job_id, PHASE_UPLOADING_REPORT,
                "Uploading JSON report to Swift",
            )
            report_swift_result = upload_json(
                json_bytes=report_bytes,
                object_name=report_object_name,
                cfg=cfg,
                log_event=coc.log_event,
            )

            # ----- PHASE: completed -----
            slo_segments = swift_result.get("slo_segments") or []
            result = {
                "acquisition_id":      acquisition_id,
                "instance_id":         instance_id,
                "instance_name":       vm_name_raw,
                "domain_name":         domain_name,
                "operator":            operator,
                "started_at":          started_at,
                "completed_at":        completed_at,
                "size_bytes":          hash_result["size_bytes"],
                "md5":                 hash_result["md5"],
                "sha1":                hash_result["sha1"],
                "etag_verified":       swift_result["etag_verified"],
                "upload_method":       swift_result.get("upload_method"),
                "slo_segments_count":  len(slo_segments),
                "dump_swift_object":   swift_result["swift_object"],
                "report_swift_object": report_swift_result["swift_object"],
            }
            jobs.complete_job(job_id, result)

            log.info(
                "[job=%s] DONE: acq=%s vm=%s size=%d md5=%s method=%s",
                job_id, acquisition_id, vm_name_raw,
                hash_result["size_bytes"], hash_result["md5"],
                swift_result.get("upload_method"),
            )

        except IntegrityError as exc:
            log.error("[job=%s] integrity failure: %s", job_id, exc)
            coc.log_event("acquisition_failed", {
                "reason": "integrity_failure",
                "error":  str(exc),
            })
            jobs.fail_job(job_id, f"Integrity verification failed: {exc}")

        except libvirt.libvirtError as exc:
            log.error("[job=%s] libvirt error: %s", job_id, exc)
            coc.log_event("acquisition_failed", {
                "reason": "libvirt_error",
                "error":  str(exc),
            })
            jobs.fail_job(job_id, f"libvirt error: {exc}")

        except (FileNotFoundError, PermissionError, OSError) as exc:
            log.error("[job=%s] filesystem error: %s", job_id, exc)
            coc.log_event("acquisition_failed", {
                "reason": "filesystem_error",
                "error":  str(exc),
            })
            jobs.fail_job(job_id, f"Filesystem error: {exc}")

        except Exception as exc:  # noqa: BLE001
            log.exception("[job=%s] unexpected error", job_id)
            coc.log_event("acquisition_failed", {
                "reason": "unexpected",
                "error":  str(exc),
            })
            jobs.fail_job(job_id, f"Internal error: {exc}")
