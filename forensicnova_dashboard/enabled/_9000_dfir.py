# Copyright 2026 Davide Numelli
# Licensed under the Apache License, Version 2.0
"""Horizon enabled file — registers the DFIR dashboard.

When Horizon scans local/enabled/ at Django startup, this file tells it:
  1. A new top-level Dashboard with slug 'dfir' must appear in the
     horizon sidebar.
  2. The Python package that contains the Dashboard subclass — i.e.
     a 'dashboard.py' module with a class inheriting horizon.Dashboard
     and calling horizon.register(...) at import time — is the one
     listed in ADD_INSTALLED_APPS.

The DASHBOARD value MUST match the slug of the Dashboard subclass in
forensicnova_dashboard/dashboards/dfir/dashboard.py.
"""

# The slug of the dashboard. Horizon uses this to wire panel groups and
# panels (declared in _9010 / _9020 / _9030) to this dashboard.
DASHBOARD = "dfir"

# Python import path of the package that contains the Dashboard subclass.
# Horizon will import '<this>.dashboard' (i.e.
# forensicnova_dashboard.dashboards.dfir.dashboard), and the side-effect
# of that import — horizon.register(Dfir) at module bottom — is what
# actually registers the dashboard in the framework.
#
# BUG NOTE (pre-fix): this used to be "forensicnova_dashboard" (the
# wrapper package), which caused Horizon to look for
# forensicnova_dashboard/dashboard.py — a file that does not exist.
# horizon.register() was never called, and any page that enumerated
# dashboards exploded with NotRegistered.
ADD_INSTALLED_APPS = ["forensicnova_dashboard.dashboards.dfir"]

# No AngularJS modules — Horizon's classic Django templates are enough.
ADD_ANGULAR_MODULES = []

# Keep the dashboard enabled. Set to True to hide it without removing
# this file.
DISABLED = False

# Default panel shown when the user clicks the 'DFIR' tab.
DEFAULT_PANEL = "acquisitions"
