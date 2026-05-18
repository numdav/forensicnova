"""DFIR top-level Horizon dashboard.

Adds a "DFIR" tab to the Horizon header for users holding the
``forensic_analyst`` Keystone role. The tab contains one panel group
("Forensics") with two panels: Acquisitions (list + detail) and
New acquisition (workflow).
"""
from django.utils.translation import gettext_lazy as _

import horizon


class ForensicsPanelGroup(horizon.PanelGroup):
    """Single panel group inside the DFIR dashboard."""
    slug = "forensics"
    name = _("Forensics")
    panels = ("acquisitions", "new_acquisition")


class Dfir(horizon.Dashboard):
    """The DFIR top-level dashboard."""
    name = _("DFIR")
    slug = "dfir"
    panels = (ForensicsPanelGroup,)
    default_panel = "acquisitions"

    # Only users carrying the forensic_analyst role see this dashboard
    # in the header. Horizon's permission middleware enforces this at
    # the URL layer: someone without the role cannot reach the panel
    # URLs even by typing them directly.
    #
    # Cross-tenant Nova read visibility for the analyst is implemented
    # in the ForensicNova plugin by granting the 'admin' role on every
    # existing project to the dfir-tester user. This is a pragmatic
    # prototype workaround; production deployments may want to tighten
    # the grant.
    permissions = ("openstack.roles.forensic_analyst",)


horizon.register(Dfir)
