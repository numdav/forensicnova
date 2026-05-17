"""Acquisitions panel — list + detail + download endpoints."""
from django.utils.translation import gettext_lazy as _

import horizon


class Acquisitions(horizon.Panel):
    name = _("Acquisitions")
    slug = "acquisitions"
    permissions = ("openstack.roles.forensic_analyst",)
