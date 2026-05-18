"""DataTable for the Acquisitions panel.

Columns chosen to maximise triage efficiency:
    - Started at        (sort default, descending)
    - VM                (link to detail; cross-tenant, so name + project_id)
    - Status            (acquired / failed)
    - Operator          (forensic analyst that ran it)
    - Size              (human-readable bytes)
    - Method            (single_put / slo with N segments)
    - Integrity         (etag verified or not)

Row actions:
    - View detail       (default link via get_link_url)
    - Download PDF      (always available)
    - Download JSON     (always available)
    - Download dump     (heavy, separate row action with confirmation)
"""
from django.utils.translation import gettext_lazy as _
from django.urls import reverse

from horizon import tables


def _format_size(bytes_val) -> str:
    """Human-readable size: 14.2 GiB / 512 MiB / etc."""
    if bytes_val is None:
        return "—"
    try:
        b = float(bytes_val)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if b < 1024.0:
            return f"{b:.1f} {unit}"
        b /= 1024.0
    return f"{b:.1f} PiB"


def _format_method(row) -> str:
    """single_put -> 'Single PUT'; slo -> 'SLO (4 segments)'."""
    method = row.get("upload_method") or "—"
    if method == "slo":
        n = row.get("slo_segments_count") or "?"
        return f"SLO ({n} segments)"
    if method == "single_put":
        return "Single PUT"
    return method


def _format_integrity(row) -> str:
    val = row.get("etag_verified")
    if val is True:
        return "✓ verified"
    if val is False:
        return "✗ FAILED"
    return "—"


class DownloadPdfAction(tables.LinkAction):
    name = "download_pdf"
    verbose_name = _("PDF")
    url = "horizon:dfir:acquisitions:download_pdf"
    classes = ("btn-secondary",)

    def get_link_url(self, datum):
        return reverse(self.url, args=(datum["acquisition_id"],))


class DownloadJsonAction(tables.LinkAction):
    name = "download_json"
    verbose_name = _("JSON")
    url = "horizon:dfir:acquisitions:download_json"
    classes = ("btn-secondary",)

    def get_link_url(self, datum):
        return reverse(self.url, args=(datum["acquisition_id"],))


class DownloadDumpAction(tables.LinkAction):
    name = "download_dump"
    verbose_name = _("Dump")
    url = "horizon:dfir:acquisitions:download_dump"
    classes = ("btn-warning",)
    # Non-block confirm shown by Horizon UI before navigation
    confirm_message = _(
        "The raw memory dump can be many GiB. "
        "Continue with download?"
    )

    def get_link_url(self, datum):
        return reverse(self.url, args=(datum["acquisition_id"],))


class AcquisitionsTable(tables.DataTable):
    started_at = tables.Column(
        "started_at",
        verbose_name=_("Started"),
    )
    # The backend acquisition summary (see _build_summary in app/api/v1.py)
    # exposes the VM name under the key 'vm_name', not 'instance_name'.
    vm_name = tables.Column(
        "vm_name",
        verbose_name=_("VM"),
        link="horizon:dfir:acquisitions:detail",
    )
    operator = tables.Column(
        "operator",
        verbose_name=_("Operator"),
    )
    size = tables.Column(
        lambda row: _format_size(row.get("size_bytes")),
        verbose_name=_("Size"),
    )
    method = tables.Column(
        _format_method,
        verbose_name=_("Method"),
    )
    integrity = tables.Column(
        _format_integrity,
        verbose_name=_("Integrity"),
    )

    class Meta:
        name = "acquisitions"
        verbose_name = _("Acquisitions")
        # The DataTable framework needs a unique id per row.
        # We use acquisition_id from the API summary.
        row_actions = (
            DownloadPdfAction,
            DownloadJsonAction,
            DownloadDumpAction,
        )

    def get_object_id(self, datum):
        return datum["acquisition_id"]
