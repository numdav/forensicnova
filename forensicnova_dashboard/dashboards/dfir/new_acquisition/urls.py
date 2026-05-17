"""URL routes for the New acquisition panel."""
from django.urls import path

from forensicnova_dashboard.dashboards.dfir.new_acquisition import views

app_name = "new_acquisition"

urlpatterns = [
    path(
        "",
        views.NewAcquisitionView.as_view(),
        name="index",
    ),
    path(
        "jobs/<str:job_id>/watch/",
        views.JobWatchView.as_view(),
        name="watch",
    ),
    path(
        "jobs/<str:job_id>/status.json",
        views.job_status_proxy,
        name="job_status",
    ),
]
