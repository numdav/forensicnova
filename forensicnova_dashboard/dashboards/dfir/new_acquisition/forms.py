"""Form for picking a target VM in the New acquisition workflow."""
from __future__ import annotations

import logging

from django import forms
from django.utils.translation import gettext_lazy as _

from forensicnova_dashboard.api import client as fn_api

LOG = logging.getLogger(__name__)


class NewAcquisitionForm(forms.Form):
    """Single-field form: choose a target VM from the cross-tenant list."""

    instance_id = forms.ChoiceField(
        label=_("Target VM"),
        help_text=_(
            "Select a Nova instance from any project. The forensic_analyst "
            "role grants cross-tenant visibility via admin role assignment "
            "on all projects."
        ),
    )

    def __init__(self, *args, request=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._request = request
        self.fields["instance_id"].choices = self._build_choices()

    def _build_choices(self) -> list[tuple[str, str]]:
        if self._request is None:
            return []
        try:
            servers = fn_api.list_servers(self._request)
        except fn_api.ForensicNovaApiError as exc:
            LOG.warning("could not load server list: %s", exc)
            return [("", _("(could not load server list)"))]

        choices: list[tuple[str, str]] = [("", _("— choose a VM —"))]
        # Only ACTIVE servers can be acquired (libvirt coreDump requires
        # the domain to be running). We list inactive ones too but flag
        # them so the operator sees why they cannot be picked.
        active = [s for s in servers if s.get("status") == "ACTIVE"]
        inactive = [s for s in servers if s.get("status") != "ACTIVE"]

        for s in active:
            label = self._format_label(s, active=True)
            choices.append((s["id"], label))

        if inactive:
            for s in inactive:
                label = self._format_label(s, active=False)
                # Disable inactive ones: we still show them so the operator
                # knows they exist, but the choice tuple's first value is
                # blank-prefixed to make submission of an inactive one a
                # validation error in clean_instance_id().
                choices.append((f"INACTIVE:{s['id']}", label))

        return choices

    @staticmethod
    def _format_label(server: dict, *, active: bool) -> str:
        name = server.get("name") or "(unnamed)"
        host = server.get("host") or "?"
        flavor = server.get("flavor_name") or "?"
        ram = server.get("ram_mb")
        ram_str = f"{ram} MiB" if ram else "?"
        status = server.get("status") or "?"
        prefix = "" if active else f"[{status}] "
        return f"{prefix}{name}  ({flavor}, {ram_str}, host={host})"

    def clean_instance_id(self) -> str:
        """Reject inactive selections and the placeholder."""
        v = self.cleaned_data["instance_id"]
        if not v:
            raise forms.ValidationError(_("Please choose a target VM."))
        if v.startswith("INACTIVE:"):
            raise forms.ValidationError(
                _("VM is not ACTIVE. libvirt coreDump requires a running "
                  "domain. Start the VM in Nova and retry.")
            )
        return v
