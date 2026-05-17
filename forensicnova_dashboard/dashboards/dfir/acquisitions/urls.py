"""URL routes for the Acquisitions panel."""
from django.urls import path

from forensicnova_dashboard.dashboards.dfir.acquisitions import views

app_name = "acquisitions"

urlpatterns = [
    path("", views.IndexView.as_view(), name="index"),
    path(
        "<str:acquisition_id>/",
        views.DetailView.as_view(),
        name="detail",
    ),
    path(
        "<str:acquisition_id>/report.pdf",
        views.download_pdf,
        name="download_pdf",
    ),
    path(
        "<str:acquisition_id>/report.json",
        views.download_json,
        name="download_json",
    ),
    path(
        "<str:acquisition_id>/dump.raw",
        views.download_dump,
        name="download_dump",
    ),
]
