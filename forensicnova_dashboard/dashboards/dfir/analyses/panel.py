"""Analyses panel — list of analyzer jobs + per-analysis detail view.

The panel surfaces the analyzer backend's job manager: every triggered
analysis (noop / volatility fast / volatility full / volatility custom)
appears here with status, duration, and links to the result JSON in
Swift once completed.
"""
from django.utils.translation import gettext_lazy as _

import horizon


class Analyses(horizon.Panel):
    name = _("Analyses")
    slug = "analyses"
    permissions = ("openstack.roles.forensic_analyst",)
