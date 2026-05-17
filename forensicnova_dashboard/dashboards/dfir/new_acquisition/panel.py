"""New acquisition panel — workflow that triggers an async acquisition."""
from django.utils.translation import gettext_lazy as _

import horizon


class NewAcquisition(horizon.Panel):
    name = _("New acquisition")
    slug = "new_acquisition"
    permissions = ("openstack.roles.forensic_analyst",)
