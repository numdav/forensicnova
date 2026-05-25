"""URL routes for the Analyses panel.

Routes:
    /                              -> IndexView      (table of analyzer jobs)
    /new/<acq_id>/                 -> NewAnalysisView (FormView)
    /jobs/<job_id>/watch/          -> JobWatchView   (polling page)
    /jobs/<job_id>/status.json     -> analyzer_job_status_proxy (poll target)
    /<analysis_id>/download.json   -> stream analysis JSON file
    /<analysis_id>/                -> DetailView     (analysis summary)

The catch-all <path:analysis_id> route MUST stay last so that the
specific prefixes /new/ and /jobs/ are matched first.
"""
from django.urls import path

from forensicnova_dashboard.dashboards.dfir.analyses import views

app_name = "analyses"

urlpatterns = [
    path("", views.IndexView.as_view(), name="index"),
    path(
        "new/<str:acquisition_id>/",
        views.NewAnalysisView.as_view(),
        name="new",
    ),
    path(
        "jobs/<str:job_id>/watch/",
        views.JobWatchView.as_view(),
        name="watch",
    ),
    path(
        "jobs/<str:job_id>/status.json",
        views.analyzer_job_status_proxy,
        name="job_status",
    ),
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
