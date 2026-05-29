"""Views for the Analyses panel.

Five views:

  IndexView   — DataTable backed by GET /api/v1/jobs (analyzer backend).
                Each row is one analyzer job; the row's status and
                analysis_id determine which row actions are available.

  NewAnalysisView (FormView) — picks analyzer / preset / plugins for a
                given acquisition_id (passed via URL). POSTs to the
                analyzer backend, captures the job_id, redirects to the
                watch page. The form is in analyses/forms.py.

  JobWatchView (TemplateView) — polling page on a single analyzer job.
                Mirrors new_acquisition/JobWatchView: a thin shell that
                calls analyzer_job_status_proxy from JS every 2s,
                renders phase/label/elapsed live, and redirects to the
                analysis detail page once status='completed'.

  analyzer_job_status_proxy — JSON proxy: takes the user's session
                cookie, forwards their Keystone token to the analyzer
                backend as X-Auth-Token, returns the job record as JSON.

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
from django.http import JsonResponse, StreamingHttpResponse
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views import generic

from horizon import exceptions, tables as horizon_tables

from forensicnova_dashboard.api import client as fn_api
from forensicnova_dashboard.dashboards.dfir.analyses import (
    forms as analysis_forms,
    tables as analysis_tables,
)

LOG = logging.getLogger(__name__)

# Placeholder used inside reverse() to build a URL template the watch
# page's JS substitutes with the real analysis_id once the job is
# done. Lets us keep Django reverse() as single source of truth for
# the URL pattern without hardcoding the dashboard prefix in JS.
_ANALYSIS_ID_PLACEHOLDER = "__ANALYSIS_ID__"


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

        # Branch by analyzer type. The volatility path keeps its existing
        # per-plugin summary table; the misp path prepares an analogous
        # IOC table plus the threat-score box, reading the misp schema's
        # own field locations (timestamps/duration are top-level, the
        # coherence flag lives under source.hashes_match_report).
        analyzer = (analysis.get("analyzer") or "").strip().lower()
        ctx["is_misp"] = (analyzer == "misp")

        if ctx["is_misp"]:
            ctx["plugins_summary"] = []  # not used in the misp template
            self._build_misp_context(ctx, analysis)
            return ctx

        # ---- volatility path (unchanged) ----------------------------
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

    @staticmethod
    def _build_misp_context(ctx, analysis):
        """Populate the context for a MISP-enrichment analysis.

        Mirrors the volatility detail layout with misp data:
          - misp_threat_score / _reason  -> coloured status box
          - misp_coherence_ok            -> source.hashes_match_report
          - misp_summary                 -> aggregate counts + actors/etc
          - misp_iocs                    -> one row per enriched IOC
                                            (the analogue of the plugin
                                            table), matched IOCs first.
        """
        summary = analysis.get("summary") or {}
        source = analysis.get("source") or {}

        ctx["misp_threat_score"] = (summary.get("threat_score") or "").lower()
        ctx["misp_threat_score_reason"] = summary.get("threat_score_reason")
        ctx["misp_coherence_ok"] = bool(source.get("hashes_match_report"))

        # Aggregate summary block (joined lists render as plain text, in
        # keeping with the lightweight style of the rest of the table).
        ctx["misp_summary"] = {
            "total_iocs_extracted": summary.get("total_iocs_extracted"),
            "total_iocs_checked":   summary.get("total_iocs_checked"),
            "total_iocs_filtered":  summary.get("total_iocs_filtered"),
            "iocs_with_misp_match": summary.get("iocs_with_misp_match"),
            "iocs_without_match":   summary.get("iocs_without_match"),
            "unique_actors":  ", ".join(summary.get("unique_actors") or []),
            "unique_galaxies": ", ".join(summary.get("unique_galaxies") or []),
            "unique_attck":   ", ".join(summary.get("unique_attck") or []),
        }

        # Main table: one row per enriched IOC. Each row carries the
        # IOC type/value, the number of MISP events it matched, and a
        # compact rollup of actors and galaxies seen across those
        # events. Matched IOCs are surfaced first (descending match
        # count) so the analyst sees the hits before the misses.
        iocs = []
        for entry in (analysis.get("enrichment") or []):
            events = entry.get("events") or []
            actors = set()
            galaxies = set()
            event_infos = []
            for ev in events:
                a = (ev.get("attribution") or {}).get("actor")
                if a:
                    actors.add(a)
                # actor_hint is heuristic; show it too but marked, so the
                # analyst can tell structured attribution from a guess.
                hint = (ev.get("attribution") or {}).get("actor_hint")
                if hint and not a:
                    actors.add(f"{hint}?")
                for g in (ev.get("galaxies") or []):
                    v = g.get("value")
                    if v:
                        galaxies.add(v)
                if ev.get("info"):
                    event_infos.append(ev["info"])
            iocs.append({
                "ioc_type":   entry.get("ioc_type"),
                "ioc_value":  entry.get("ioc_value"),
                "context":    entry.get("context"),
                "misp_match": entry.get("misp_match") or 0,
                "actors":     ", ".join(sorted(actors)),
                "galaxies":   ", ".join(sorted(galaxies)),
                "event_info": "; ".join(event_infos[:3]),
            })
        iocs.sort(key=lambda x: -(x.get("misp_match") or 0))
        ctx["misp_iocs"] = iocs


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


# ---------------------------------------------------------------------------
# New analysis — FormView that submits a POST to the analyzer backend
# ---------------------------------------------------------------------------

class NewAnalysisView(generic.FormView):
    """Pick analyzer/preset/plugins for one acquisition_id, then trigger.

    The acquisition_id is captured from the URL (not the form), so the
    page is opened by clicking the 'Analyze' action on the Acquisitions
    table — no risk of accidentally analyzing the wrong acquisition by
    selecting the wrong VM in a dropdown.
    """
    template_name = "dfir/analyses/new.html"
    form_class = analysis_forms.NewAnalysisForm
    page_title = _("New analysis")

    def get_form_kwargs(self):
        kw = super().get_form_kwargs()
        kw["request"] = self.request
        kw["acquisition_id"] = self.kwargs.get("acquisition_id")
        return kw

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["acquisition_id"] = self.kwargs.get("acquisition_id")
        return ctx

    def form_valid(self, form):
        acquisition_id = self.kwargs["acquisition_id"]
        analyzer = form.cleaned_data["analyzer"]
        preset = form.cleaned_data.get("preset") or None
        plugins = form.cleaned_data.get("plugins") or None

        LOG.info(
            "horizon -> trigger analysis: user=%s acq=%s analyzer=%s "
            "preset=%s plugins=%s",
            getattr(self.request.user, "username", "?"),
            acquisition_id, analyzer, preset, plugins,
        )
        try:
            resp = fn_api.trigger_analysis(
                self.request, acquisition_id,
                analyzer=analyzer, preset=preset, plugins=plugins,
            )
        except fn_api.ForensicNovaUnavailable as exc:
            messages.error(
                self.request,
                _("Analyzer service is unreachable: %s") % exc,
            )
            return self.form_invalid(form)
        except fn_api.ForensicNovaForbidden:
            messages.error(
                self.request,
                _("Backend rejected the request (403). "
                  "Check the forensic_analyst role."),
            )
            return self.form_invalid(form)
        except fn_api.ForensicNovaNotFound:
            messages.error(
                self.request,
                _("Acquisition %s not found in the analyzer backend.")
                % acquisition_id,
            )
            return self.form_invalid(form)
        except fn_api.ForensicNovaApiError as exc:
            # The analyzer backend returns 400 with a structured
            # message for unsupported_preset / unknown_plugins / etc.
            # Show the message verbatim — it carries the diagnostic
            # the analyst needs to fix the request.
            messages.error(
                self.request,
                _("Trigger failed: %s") % exc,
            )
            return self.form_invalid(form)

        job_id = resp.get("job_id")
        if not job_id:
            messages.error(
                self.request,
                _("Backend did not return a job_id."),
            )
            return self.form_invalid(form)

        messages.info(
            self.request,
            _("Analysis started — watching progress…"),
        )
        from django.shortcuts import redirect
        return redirect(
            "horizon:dfir:analyses:watch", job_id=job_id,
        )


# ---------------------------------------------------------------------------
# Job watch — polling page for an in-flight analysis
# ---------------------------------------------------------------------------

class JobWatchView(generic.TemplateView):
    """Render a polling page for an analyzer job.

    Same pattern as new_acquisition/JobWatchView, adapted to the
    analyzer backend: the JS polls analyzer_job_status_proxy every 2s
    and renders status/phase/elapsed live. On completion it redirects
    to the analysis detail page, NOT the acquisitions detail page.
    """
    template_name = "dfir/analyses/watch.html"
    page_title = _("Analysis in progress")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        job_id = self.kwargs["job_id"]
        ctx["job_id"] = job_id

        try:
            job = fn_api.get_analyzer_job(self.request, job_id)
            ctx["initial_status"] = job.get("status")
            ctx["initial_phase_label"] = job.get("label", "")
            ctx["acquisition_id"] = job.get("acquisition_id") or ""
            ctx["analyzer"] = job.get("analyzer") or ""
            ctx["preset"] = job.get("preset") or ""
            # If already completed by the time the user loads this
            # page (rare race) — set a courtesy direct link too.
            if job.get("status") == "completed":
                analysis_id = job.get("analysis_id")
                if analysis_id:
                    ctx["completed_redirect_url"] = reverse(
                        "horizon:dfir:analyses:detail",
                        args=(analysis_id,),
                    )
        except fn_api.ForensicNovaApiError as exc:
            LOG.warning("watch first-paint read failed: %s", exc)
            ctx["initial_status"] = "pending"
            ctx["initial_phase_label"] = ""
            ctx["acquisition_id"] = ""
            ctx["analyzer"] = ""
            ctx["preset"] = ""

        # URL the JS polls — points at the Horizon proxy so the
        # browser's session cookie authenticates without exposing
        # any X-Auth-Token to JavaScript.
        ctx["poll_url"] = reverse(
            "horizon:dfir:analyses:job_status",
            args=(job_id,),
        )
        ctx["analyses_index_url"] = reverse(
            "horizon:dfir:analyses:index",
        )
        # URL template built via Django reverse() with a placeholder.
        # The watch JS substitutes the real analysis_id at runtime
        # via a plain string replace — keeping reverse() as the
        # single source of truth for the URL pattern.
        ctx["analysis_detail_url_template"] = reverse(
            "horizon:dfir:analyses:detail",
            args=(_ANALYSIS_ID_PLACEHOLDER,),
        )
        return ctx


def analyzer_job_status_proxy(request, job_id: str):
    """Tiny JSON proxy from Horizon to the analyzer backend.

    The watch JS calls this URL; this code forwards the user's
    Keystone token to the analyzer service and returns the job record
    verbatim. Bridges the gap between browser session cookie
    (authenticates with Horizon) and analyzer auth (X-Auth-Token).
    """
    try:
        job = fn_api.get_analyzer_job(request, job_id)
    except fn_api.ForensicNovaNotFound:
        return JsonResponse({"error": "not_found"}, status=404)
    except fn_api.ForensicNovaApiError as exc:
        return JsonResponse(
            {"error": "backend", "detail": str(exc)},
            status=502,
        )
    return JsonResponse(job)
