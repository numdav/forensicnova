"""Views for the New acquisition panel.

Two views:

  - NewAcquisitionView (FormView)
        Renders the "pick a VM" form. On POST, calls
        fn_api.trigger_acquisition() — which returns 202 Accepted with
        a job_id — and redirects to the watch view. The trigger does
        not block: the actual pipeline runs in a background thread on
        the ForensicNova service.

  - JobWatchView (TemplateView)
        Renders a polling page that hits fn_api.get_job() every
        2 seconds. Displays phase_label + elapsed_seconds. On
        status='completed' redirects the browser to the acquisition
        detail page. On status='failed' shows the error.

  Why a polling page and not a websocket: simple, no extra deps, no
  server-side state beyond what JobManager already persists. Polling
  load is a few requests every couple of seconds — the GET /jobs/<id>
  endpoint is a cheap JSON read of a single file.

  Why no fake percentages: libvirt does not expose dump progress; the
  hash phase is fast; only SLO segments give exact step counts. We
  intentionally show only "phase + elapsed", which is honest to what
  the backend can actually report.
"""
from __future__ import annotations

import logging

from django.contrib import messages
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views import generic

from forensicnova_dashboard.api import client as fn_api
from forensicnova_dashboard.dashboards.dfir.new_acquisition import forms

LOG = logging.getLogger(__name__)


class NewAcquisitionView(generic.FormView):
    template_name = "dfir/new_acquisition/new.html"
    form_class = forms.NewAcquisitionForm
    page_title = _("New acquisition")

    def get_form_kwargs(self):
        kw = super().get_form_kwargs()
        kw["request"] = self.request
        return kw

    def form_valid(self, form):
        instance_id = form.cleaned_data["instance_id"]
        LOG.info(
            "horizon -> trigger acquisition: user=%s instance=%s",
            getattr(self.request.user, "username", "?"),
            instance_id,
        )
        try:
            resp = fn_api.trigger_acquisition(self.request, instance_id)
        except fn_api.ForensicNovaUnavailable as exc:
            messages.error(
                self.request,
                _("ForensicNova service is unreachable: %s") % exc,
            )
            return self.form_invalid(form)
        except fn_api.ForensicNovaForbidden:
            messages.error(
                self.request,
                _("Backend rejected the request (403). "
                  "Check the forensic_analyst role assignment."),
            )
            return self.form_invalid(form)
        except fn_api.ForensicNovaApiError as exc:
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
            _("Acquisition started — watching progress…"),
        )
        return self._redirect_to_watch(job_id)

    def _redirect_to_watch(self, job_id: str):
        from django.shortcuts import redirect
        return redirect(
            "horizon:dfir:new_acquisition:watch", job_id=job_id,
        )


# Placeholder used inside reverse() to build a URL template the watch
# page's JS can later substitute with the real acquisition_id. Using a
# placeholder + JS replace() lets us keep Django reverse() as the
# single source of truth for the URL pattern, without hardcoding the
# /dashboard/dfir/... prefix in JavaScript.
_ACQ_ID_PLACEHOLDER = "__ACQ_ID__"


class JobWatchView(generic.TemplateView):
    template_name = "dfir/new_acquisition/watch.html"
    page_title = _("Acquisition in progress")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        job_id = self.kwargs["job_id"]
        ctx["job_id"] = job_id

        # First-paint values — JS will overwrite them with authoritative
        # data from the first poll round trip. We do this read here so
        # that if the job is already terminal (rare race), we can short
        # circuit instead of showing a "queued" placeholder.
        try:
            job = fn_api.get_job(self.request, job_id)
            ctx["initial_status"] = job.get("status")
            # The backend job record exposes the human-readable phase
            # label under the key 'label' (and the machine-readable phase
            # under 'phase'). Older versions of this template referred
            # to a non-existent 'phase_label' key.
            ctx["initial_phase_label"] = job.get("label", "")
            ctx["instance_name"] = job.get("instance_name") or ""
            # If already completed, JS will redirect immediately on first
            # poll, but we put the link in context as a courtesy too.
            if job.get("status") == "completed":
                acq_id = (job.get("result") or {}).get("acquisition_id")
                if acq_id:
                    ctx["completed_redirect_url"] = reverse(
                        "horizon:dfir:acquisitions:detail",
                        args=(acq_id,),
                    )
        except fn_api.ForensicNovaApiError as exc:
            LOG.warning("watch first-paint read failed: %s", exc)
            ctx["initial_status"] = "pending"
            ctx["initial_phase_label"] = ""
            ctx["instance_name"] = ""

        # URL the JS will poll. We point at the Horizon proxy below
        # rather than the raw backend, so the user's session cookie
        # works without exposing X-Auth-Token to JS.
        ctx["poll_url"] = reverse(
            "horizon:dfir:new_acquisition:job_status",
            args=(job_id,),
        )
        ctx["acquisitions_index_url"] = reverse(
            "horizon:dfir:acquisitions:index",
        )
        # Template URL the watch JS will use to redirect to the
        # acquisition detail page once the job completes. Built via
        # Django reverse() with a placeholder so the JS only does a
        # plain string replace — no hardcoded URL prefix in JavaScript.
        ctx["acquisition_detail_url_template"] = reverse(
            "horizon:dfir:acquisitions:detail",
            args=(_ACQ_ID_PLACEHOLDER,),
        )
        return ctx


def job_status_proxy(request, job_id: str):
    """Tiny JSON proxy: the watch JS hits this; this hits ForensicNova.

    Why a proxy: the browser's session cookie authenticates with Horizon,
    but the ForensicNova REST needs an X-Auth-Token. The proxy bridges
    the two: it runs on the server side, where the request object holds
    both the user's session AND the Keystone token, and forwards the
    token to the backend.
    """
    from django.http import JsonResponse
    try:
        job = fn_api.get_job(request, job_id)
    except fn_api.ForensicNovaNotFound:
        return JsonResponse({"error": "not_found"}, status=404)
    except fn_api.ForensicNovaApiError as exc:
        return JsonResponse(
            {"error": "backend", "detail": str(exc)},
            status=502,
        )
    return JsonResponse(job)
