"""DataTable for the Analyses panel.

Backed by GET /api/v1/jobs (analyzer backend). Each row is one analyzer
job; the columns surface what matters for DFIR triage:

  - Started at         (default sort, newest first)
  - Acquisition        (link to acquisitions detail)
  - Analyzer + preset  (volatility/fast / full / custom)
  - Status             (pending / running / completed / failed)
  - Duration           (elapsed_seconds, human-readable)
  - Operator           (Keystone user that triggered it)

Row actions:
  - View result        (only if completed, link to detail view)
  - Download JSON      (only if completed, stream from Swift)
  - Delete             (any state — cascades Swift cleanup on completed jobs)
"""
import logging

from django.utils.translation import gettext_lazy as _
from django.utils.translation import ngettext_lazy
from django.urls import reverse

from horizon import exceptions
from horizon import tables

from forensicnova_dashboard.api import client as fn_api

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

def _format_analyzer_preset(row) -> str:
    """'volatility/fast', 'volatility/custom (3 plugins)' ..."""
    analyzer = row.get("analyzer") or "—"
    preset = row.get("preset")
    if preset:
        if preset == "custom":
            plugins = row.get("plugins") or []
            return f"{analyzer}/{preset} ({len(plugins)} plugins)"
        return f"{analyzer}/{preset}"
    return analyzer


def _format_status(row) -> str:
    """Status with a glyph for quick visual scanning.

    For in-flight jobs (pending/running) the per-plugin progress label
    is appended after the status word, e.g.:
        "▶ running — plugin 17/34: windows.malware.suspicious_threads.SuspiciousThreads"
    The label originates from the analyzer's on_plugin_start callback
    (volatility.py) and is persisted via JobManager.update_label, so
    this surfaces the same fine-grained progress signal that the watch
    page polls — just without the auto-refresh (operator hits F5).

    For completed/failed jobs only the glyph + status is shown, since
    the per-plugin label would be stale.
    """
    status = row.get("status") or "unknown"
    glyph = {
        "pending":   "⋯",
        "running":   "▶",
        "completed": "✓",
        "failed":    "✗",
    }.get(status, "?")
    base = f"{glyph} {status}"
    # Append the current per-plugin label only while the job is moving.
    # The label is the human-readable progress string ("Running plugin
    # N/Total: <name>"); when present we trim its "Running plugin"
    # prefix to keep the column compact.
    if status in ("pending", "running"):
        label = (row.get("label") or "").strip()
        if label and label.lower().startswith("running plugin"):
            # "Running plugin 17/34: ..." -> "plugin 17/34: ..."
            label = label[len("Running "):]
        if label and label.lower() != "running":
            return f"{base} — {label}"
    return base


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


class WatchProgressAction(tables.LinkAction):
    """Open the live watch page for an in-flight (pending/running) job.

    Complementary to ViewResultAction: ViewResult opens the completed
    analysis detail; this one opens the polling watch page so the
    operator can monitor per-plugin progress (e.g. "Running plugin
    17/34: windows.malware.suspicious_threads.SuspiciousThreads")
    without having to construct the URL by hand.

    Visibility: only shown for jobs in 'pending' or 'running' state.
    Once a job moves to 'completed' or 'failed' this action disappears
    and ViewResultAction (or the row's row-error state) takes over.

    The URL is the analyses:watch route (urls.py) which takes job_id.
    job_id is exactly what get_object_id returns for this table, so
    Horizon's action plumbing wires up automatically.
    """
    name = "watch_progress"
    verbose_name = _("Watch")
    url = "horizon:dfir:analyses:watch"
    classes = ("btn-info",)

    def allowed(self, request, datum=None):
        return bool(datum and datum.get("status") in ("pending", "running"))

    def get_link_url(self, datum):
        return reverse(self.url, kwargs={"job_id": datum["job_id"]})


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


class DeleteAnalysisAction(tables.DeleteAction):
    """Delete an analyzer job + cascade-delete its Swift analysis JSON.

    Horizon-managed flow:
      - User selects rows (or clicks the inline button on a single row)
        and confirms via the standard Horizon delete confirmation modal.
      - Horizon calls this action's .delete(request, obj_id) once per
        selected row. obj_id is the job_id (defined by
        AnalysesTable.get_object_id).
      - On any failure inside delete(), Horizon re-raises so the
        framework can surface an error message; on success the row
        disappears from the next page render.

    Visibility:
      Allowed on every status. The backend endpoint is idempotent and
      lets the operator delete failed jobs, pending jobs (rare, but
      possible if a job was stuck in PENDING after a restart that
      recover_on_startup didn't catch in time), or completed jobs.
      Status-based gating would only hide a useful cleanup operation.

    Cascade semantics:
      Failed/pending/running jobs do NOT have a Swift analysis-*.json,
      so only the local job file is removed. Completed jobs trigger
      the Swift cascade in the backend. The result of either leg is
      surfaced to the operator through Horizon's standard success
      notification (just "Deleted Analysis: <id>" — we do NOT inject
      a per-row info message about cascade details to keep the UX
      consistent with the rest of Horizon).
    """
    name = "delete_analysis"

    # action_present/past are required by Horizon to render bulk-action
    # button labels ("Delete Analysis" / "Delete Analyses") and the
    # success/failure summary ("Deleted 3 Analyses").
    @staticmethod
    def action_present(count):
        return ngettext_lazy(
            "Delete Analysis",
            "Delete Analyses",
            count,
        )

    @staticmethod
    def action_past(count):
        return ngettext_lazy(
            "Deleted Analysis",
            "Deleted Analyses",
            count,
        )

    def delete(self, request, obj_id):
        """Cascade-delete via the analyzer backend.

        obj_id == job_id (see AnalysesTable.get_object_id). The backend
        endpoint is idempotent; we still catch the typed API exceptions
        so Horizon's red-toast error message carries something more
        precise than "ServerError 500".
        """
        try:
            result = fn_api.delete_analyzer_job(request, obj_id)
        except fn_api.ForensicNovaUnavailable as exc:
            LOG.warning("delete: analyzer unreachable for job=%s: %s",
                        obj_id, exc)
            raise exceptions.NotAvailable(
                _("Analyzer service is unreachable: %s") % exc,
            )
        except fn_api.ForensicNovaForbidden as exc:
            LOG.warning("delete: forbidden for job=%s: %s", obj_id, exc)
            raise exceptions.NotAuthorized(
                _("Backend rejected the delete request (403). "
                  "Check the forensic_analyst role."),
            )
        except fn_api.ForensicNovaApiError as exc:
            LOG.warning("delete: backend error for job=%s: %s", obj_id, exc)
            # Generic Horizon exception path so the framework renders
            # a red toast with our message verbatim.
            raise exceptions.HorizonException(
                _("Delete failed: %s") % exc,
            )

        # Informational log: surfaces what the backend actually removed.
        # Especially useful for post-unstack/stack cleanup of orphans.
        LOG.info(
            "deleted analyzer job=%s removed_job=%s swift_cascade=%s "
            "(was status=%s, analyzer=%s, analysis_id=%s)",
            obj_id,
            result.get("removed_job"),
            (result.get("cascade_swift") or {}).get("status"),
            result.get("previous_status"),
            result.get("analyzer"),
            result.get("analysis_id"),
        )


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
        # Action ordering: Watch comes first because it's the only
        # action visible during a running job (the other two are
        # gated on status=completed). Putting it first puts the
        # primary action at the leftmost position consistently for
        # both in-flight and completed rows.
        row_actions = (
            WatchProgressAction,
            ViewResultAction,
            DownloadJsonAction,
            DeleteAnalysisAction,
        )
        # table_actions enables the bulk-delete button in the table
        # header (multi-select then "Delete Analyses"). Same action
        # class, Horizon uses action_present(count) to label it.
        table_actions = (
            DeleteAnalysisAction,
        )

    def get_object_id(self, datum):
        # job_id is the unique key per row. analysis_id only exists
        # once the job has completed, so it cannot be the row id.
        return datum["job_id"]
