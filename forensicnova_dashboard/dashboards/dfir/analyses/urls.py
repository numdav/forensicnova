"""URL routes for the Analyses panel.

Routes:
    /              -> IndexView (table of analyzer jobs)
    /<analysis_id> -> DetailView (single analysis JSON, summary + download)
    /<analysis_id>/download.json -> stream the analysis JSON file
"""
from django.urls import path

from forensicnova_dashboard.dashboards.dfir.analyses import views

app_name = "analyses"

urlpatterns = [
    path("", views.IndexView.as_view(), name="index"),
    path(
        "<path:analysis_id>/download.json",
        views.download_json,
        name="download_json",
    ),
    path(
        "<path:analysis_id>/",
        views.DetailView.as_view(),
        name="detail",
    ),
]
