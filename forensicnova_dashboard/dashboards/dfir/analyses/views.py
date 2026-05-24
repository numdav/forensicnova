"""Views for the Analyses panel.

Three views:

  IndexView   — DataTable backed by GET /api/v1/jobs (analyzer backend).
                Each row is one analyzer job; the row's status and
                analysis_id determine which row actions are available.

  DetailView  — Renders the analysis JSON for one analysis_id. Shows
                meta fields (analyzer, preset, durations, coherence
                check) and a per-plugin summary table. The raw JSON is
                downloadable separately to avoid embedding multi-MB
                payloads in the HTML response.

  download_json — Proxies the analysis JSON straight from the analyzer
                  service to the browser (StreamingHttpResponse) with a
                  filename hint, so the operator gets a clean download.

The error handling mirrors acquisitions/views.py: catch the typed
exceptions raised by the api client, display a Horizon message, and
return an empty payload rather than a 500.
"""
from __future__ import annotations

import logging

from django.contrib import messages
from django.http import StreamingHttpResponse
from django.utils.translation import gettext_lazy as _
from django.views import generic

from horizon import exceptions, tables as horizon_tables

from forensicnova_dashboard.api import client as fn_api
from forensicnova_dashboard.dashboards.dfir.analyses import (
    tables as analysis_tables,
)

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Index — table of analyzer jobs
# ---------------------------------------------------------------------------

class IndexView(horizon_tables.DataTableView):
    """List of analyzer jobs, most recent first.

    Driven by GET /api/v1/jobs on the analyzer backend. Job records
    contain status (pending/running/completed/failed), phase, label,
    started_at, elapsed_seconds, analyzer, preset, plugins, and
    analysis_id (only when status == "completed"). The table layout
    is defined in tables.py.
    """
    table_class = analysis_tables.AnalysesTable
    template_name = "dfir/analyses/index.html"
    page_title = _("Analyses")

    def get_data(self):
        try:
            return fn_api.list_analyzer_jobs(self.request)
        except fn_api.ForensicNovaUnavailable as exc:
            messages.error(
                self.request,
                _("ForensicNova analyzer service is unreachable: %s") % exc,
            )
            exceptions.handle(self.request, ignore=True)
            return []
        except fn_api.ForensicNovaForbidden:
            messages.error(
                self.request,
                _("Your account lacks the forensic_analyst role."),
            )
            exceptions.handle(self.request, ignore=True)
            return []
        except fn_api.ForensicNovaApiError as exc:
            messages.error(
                self.request,
                _("Could not list analyses: %s") % exc,
            )
            exceptions.handle(self.request, ignore=True)
            return []


# ---------------------------------------------------------------------------
# Detail — single analysis JSON
# ---------------------------------------------------------------------------

class DetailView(generic.TemplateView):
    """Render a single analysis (minimal view + download link).

    Fetches the full analysis JSON from the analyzer backend and
    surfaces:
      - meta: analyzer, preset, os_hint, duration, hash_phase_seconds
      - coherence_check: hashes_match_report
      - per-plugin summary table: plugin, status, row_count, duration

    The raw JSON download link points at download_json (streaming
    proxy), keeping the HTML page light even for full-preset analyses
    that emit hundreds of KB of plugin rows.
    """
    template_name = "dfir/analyses/detail.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        analysis_id = self.kwargs["analysis_id"]
        ctx["analysis_id"] = analysis_id

        try:
            analysis = fn_api.get_analysis(self.request, analysis_id)
        except fn_api.ForensicNovaNotFound:
            messages.error(
                self.request,
                _("Analysis %s not found.") % analysis_id,
            )
            ctx["analysis"] = None
            ctx["plugins_summary"] = []
            return ctx
        except fn_api.ForensicNovaApiError as exc:
            messages.error(
                self.request,
                _("Could not load analysis: %s") % exc,
            )
            ctx["analysis"] = None
            ctx["plugins_summary"] = []
            return ctx

        ctx["analysis"] = analysis

        # Flatten plugin results into a sortable list of dicts for the
        # template. We do NOT pass the raw rows array (potentially
        # thousands of records) — the user downloads JSON for that.
        result = analysis.get("result") or {}
        plugins = result.get("plugins") or {}
        plugins_summary = []
        for plugin_name, p in plugins.items():
            plugins_summary.append({
                "plugin":           plugin_name,
                "status":           p.get("status"),
                "row_count":        p.get("row_count"),
                "duration_seconds": p.get("duration_seconds"),
                "error_message":    p.get("error_message"),
            })
        # Order by duration descending (slowest first) — typically the
        # plugins the analyst wants to inspect immediately.
        plugins_summary.sort(
            key=lambda x: -(x.get("duration_seconds") or 0),
        )
        ctx["plugins_summary"] = plugins_summary
        return ctx


# ---------------------------------------------------------------------------
# Download — proxy JSON stream
# ---------------------------------------------------------------------------

def download_json(request, analysis_id: str):
    """Stream the raw analysis JSON to the browser as an attachment."""
    try:
        upstream = fn_api.stream_analysis_json(request, analysis_id)
    except fn_api.ForensicNovaNotFound:
        messages.error(
            request, _("Analysis %s not found.") % analysis_id,
        )
        return _redirect_to_index()
    except fn_api.ForensicNovaApiError as exc:
        messages.error(request, _("JSON download failed: %s") % exc)
        return _redirect_to_index()

    resp = StreamingHttpResponse(
        upstream.iter_content(chunk_size=64 * 1024),
        content_type=upstream.headers.get("Content-Type", "application/json"),
    )
    # Force browser download with the analysis_id as filename.
    resp["Content-Disposition"] = f'attachment; filename="{analysis_id}"'
    cl = upstream.headers.get("Content-Length")
    if cl:
        resp["Content-Length"] = cl
    return resp


def _redirect_to_index():
    from django.shortcuts import redirect
    return redirect("horizon:dfir:analyses:index")
