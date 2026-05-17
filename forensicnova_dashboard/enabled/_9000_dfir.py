# Copyright 2026 Davide Numelli
# Licensed under the Apache License, Version 2.0
"""Horizon enabled file — registers the DFIR dashboard.

The DASHBOARD value MUST match the slug of the Dashboard subclass in
forensicnova_dashboard/dashboards/dfir/dashboard.py.

ADD_INSTALLED_APPS makes Django discover templates, urls.py, and the
panel.py modules within the package.

ADD_EXCEPTIONS lets us route ForensicNova's API errors to a clean
flash message instead of a 500 page.
"""

# The slug of the dashboard to be added to HORIZON['dashboards'].
# Must match Dfir.slug in dashboards/dfir/dashboard.py.
DASHBOARD = "dfir"

# Optional: enable the dashboard on Horizon load.
ADD_INSTALLED_APPS = ["forensicnova_dashboard"]

# Module path for the Dashboard class itself (Horizon imports this).
ADD_ANGULAR_MODULES = []

# Where Horizon should look for the Dashboard class.
DISABLED = False

DEFAULT_PANEL = "acquisitions"
