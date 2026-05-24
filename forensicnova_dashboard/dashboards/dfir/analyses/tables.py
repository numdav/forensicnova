"""DataTable for the Analyses panel.

Backed by GET /api/v1/jobs (analyzer backend). Each row is one analyzer
job; the columns surface what matters for DFIR triage:

  - Started at         (default sort, newest first)
  - Acquisition        (link to acquisitions detail)
  - Analyzer + preset  (noop / volatility / fast / full / custom)
  - Status             (pending / running / completed / failed)
  - Duration           (elapsed_seconds, human-readable)
  - Operator           (Keystone user that triggered it)

Row actions:
  - View result        (only if completed, link to detail view)
  - Download JSON      (only if completed, stream from Swift)
"""
from django.utils.translation import gettext_lazy as _
from django.urls import reverse

from horizon import tables


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

def _format_analyzer_preset(row) -> str:
    """'volatility/fast', 'noop', 'volatility/custom' (3 plugins) ..."""
    analyzer = row.get("analyzer") or "—"
    preset = row.get("preset")
    if preset:
        if preset == "custom":
            plugins = row.get("plugins") or []
            return f"{analyzer}/{preset} ({len(plugins)} plugins)"
        return f"{analyzer}/{preset}"
    return analyzer


def _format_status(row) -> str:
    """Status with a glyph for quick visual scanning."""
    status = row.get("status") or "unknown"
    glyph = {
        "pending":   "⋯",
        "running":   "▶",
        "completed": "✓",
        "failed":    "✗",
    }.get(status, "?")
    return f"{glyph} {status}"


def _format_duration(row) -> str:
    """Elapsed seconds, formatted as `Mm Ss` or `Ss`."""
    val = row.get("elapsed_seconds")
    if val is None:
        return "—"
    try:
        s = int(val)
    except (TypeError, ValueError):
        return "—"
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    return f"{m}m {s:02d}s"


def _format_acquisition_link(row):
    """Acquisition_id as plain text — link wiring is via Column(link=...)."""
    return row.get("acquisition_id") or "—"


# ---------------------------------------------------------------------------
# Row actions
# ---------------------------------------------------------------------------

class ViewResultAction(tables.LinkAction):
    """Open the analysis detail view. Only visible on completed jobs."""
    name = "view_result"
    verbose_name = _("View")
    url = "horizon:dfir:analyses:detail"
    classes = ("btn-primary",)

    def allowed(self, request, datum=None):
        return bool(datum and datum.get("status") == "completed"
                    and datum.get("analysis_id"))

    def get_link_url(self, datum):
        return reverse(self.url, args=(datum["analysis_id"],))


class DownloadJsonAction(tables.LinkAction):
    """Download the raw analysis JSON. Only visible on completed jobs."""
    name = "download_json"
    verbose_name = _("JSON")
    url = "horizon:dfir:analyses:download_json"
    classes = ("btn-secondary",)

    def allowed(self, request, datum=None):
        return bool(datum and datum.get("status") == "completed"
                    and datum.get("analysis_id"))

    def get_link_url(self, datum):
        return reverse(self.url, args=(datum["analysis_id"],))


# ---------------------------------------------------------------------------
# Table
# ---------------------------------------------------------------------------

class AnalysesTable(tables.DataTable):
    started_at = tables.Column(
        "started_at",
        verbose_name=_("Started"),
    )
    # Acquisition link points to the acquisitions detail view (a job
    # may target an acquisition that's no longer in our list if it was
    # deleted post-job; in that case the link 404s, which is correct
    # behaviour rather than masking the broken reference).
    acquisition = tables.Column(
        _format_acquisition_link,
        verbose_name=_("Acquisition"),
    )
    analyzer = tables.Column(
        _format_analyzer_preset,
        verbose_name=_("Analyzer / Preset"),
    )
    status = tables.Column(
        _format_status,
        verbose_name=_("Status"),
    )
    duration = tables.Column(
        _format_duration,
        verbose_name=_("Duration"),
    )
    operator = tables.Column(
        "operator",
        verbose_name=_("Operator"),
    )

    class Meta:
        name = "analyses"
        verbose_name = _("Analyses")
        row_actions = (
            ViewResultAction,
            DownloadJsonAction,
        )

    def get_object_id(self, datum):
        # job_id is the unique key per row. analysis_id only exists
        # once the job has completed, so it cannot be the row id.
        return datum["job_id"]
