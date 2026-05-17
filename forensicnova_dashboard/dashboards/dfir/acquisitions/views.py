"""Views for the Acquisitions panel."""
from __future__ import annotations

import logging

from django.contrib import messages
from django.http import StreamingHttpResponse
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views import generic

from horizon import exceptions, tables as horizon_tables

from forensicnova_dashboard.api import client as fn_api
from forensicnova_dashboard.dashboards.dfir.acquisitions import (
    tables as acq_tables,
)

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Index — paginated list of all acquisitions
# ---------------------------------------------------------------------------

class IndexView(horizon_tables.DataTableView):
    table_class = acq_tables.AcquisitionsTable
    template_name = "dfir/acquisitions/index.html"
    page_title = _("Acquisitions")

    def get_data(self):
        try:
            return fn_api.list_acquisitions(self.request)
        except fn_api.ForensicNovaUnavailable as exc:
            messages.error(
                self.request,
                _("ForensicNova service is unreachable: %s") % exc,
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
                _("Could not list acquisitions: %s") % exc,
            )
            exceptions.handle(self.request, ignore=True)
            return []


# ---------------------------------------------------------------------------
# Detail — full report rendering
# ---------------------------------------------------------------------------

class DetailView(generic.TemplateView):
    template_name = "dfir/acquisitions/detail.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        acq_id = self.kwargs["acquisition_id"]
        try:
            ctx["report"] = fn_api.get_acquisition(self.request, acq_id)
        except fn_api.ForensicNovaNotFound:
            messages.error(
                self.request,
                _("Acquisition %s not found.") % acq_id,
            )
            ctx["report"] = None
        except fn_api.ForensicNovaApiError as exc:
            messages.error(
                self.request,
                _("Could not load acquisition: %s") % exc,
            )
            ctx["report"] = None
        ctx["acquisition_id"] = acq_id
        return ctx


# ---------------------------------------------------------------------------
# Download proxies — stream from ForensicNova to the browser
# ---------------------------------------------------------------------------

def _proxy_stream(request, upstream_resp, default_filename: str):
    """Build a Django StreamingHttpResponse that pipes upstream_resp through.

    Forwards Content-Type, Content-Length, Content-Disposition. Uses an
    iterator over upstream_resp.iter_content so the browser starts
    downloading without buffering the whole body in Horizon.
    """
    resp = StreamingHttpResponse(
        upstream_resp.iter_content(chunk_size=64 * 1024),
        content_type=upstream_resp.headers.get(
            "Content-Type", "application/octet-stream"),
    )
    cd = upstream_resp.headers.get("Content-Disposition")
    if cd:
        resp["Content-Disposition"] = cd
    else:
        resp["Content-Disposition"] = f'attachment; filename="{default_filename}"'
    cl = upstream_resp.headers.get("Content-Length")
    if cl:
        resp["Content-Length"] = cl
    return resp


def download_pdf(request, acquisition_id: str):
    try:
        upstream = fn_api.stream_pdf(request, acquisition_id)
    except fn_api.ForensicNovaApiError as exc:
        messages.error(request, _("PDF download failed: %s") % exc)
        return _redirect_to_index()
    return _proxy_stream(
        request, upstream,
        default_filename=f"forensicnova-{acquisition_id}.pdf",
    )


def download_json(request, acquisition_id: str):
    try:
        upstream = fn_api.stream_json_report(request, acquisition_id)
    except fn_api.ForensicNovaApiError as exc:
        messages.error(request, _("JSON download failed: %s") % exc)
        return _redirect_to_index()
    return _proxy_stream(
        request, upstream,
        default_filename=f"forensicnova-{acquisition_id}.json",
    )


def download_dump(request, acquisition_id: str):
    try:
        upstream = fn_api.stream_dump(request, acquisition_id)
    except fn_api.ForensicNovaApiError as exc:
        messages.error(request, _("Dump download failed: %s") % exc)
        return _redirect_to_index()
    return _proxy_stream(
        request, upstream,
        default_filename=f"forensicnova-{acquisition_id}.raw",
    )


def _redirect_to_index():
    from django.shortcuts import redirect
    return redirect("horizon:dfir:acquisitions:index")
