# Copyright 2026 Davide Numelli
"""Register the Analyses panel inside the forensics group.

Load order 9025 places this panel between Acquisitions (9020) and
NewAcquisition (9030), so it appears in the sidebar right after
Acquisitions — which is the most natural reading order ("see what
I acquired, then see what I analysed").
"""

PANEL = "analyses"
PANEL_DASHBOARD = "dfir"
PANEL_GROUP = "forensics"

ADD_PANEL = (
    "forensicnova_dashboard.dashboards.dfir.analyses.panel.Analyses"
)
