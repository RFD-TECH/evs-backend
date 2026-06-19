"""EVS institutions URL configuration."""
from django.urls import include, path
from rest_framework.routers import SimpleRouter

from . import views

institution_router = SimpleRouter(trailing_slash=False)
institution_router.register("", views.InstitutionViewSet, basename="institution")

cycle_router = SimpleRouter(trailing_slash=False)
cycle_router.register("cycles", views.GraduationCycleViewSet, basename="graduation-cycle")

urlpatterns = [
    path("", include(institution_router.urls)),
    path("<uuid:institution_pk>/", include(cycle_router.urls)),
    path("sla/status", views.SlaStatusView.as_view(), name="sla-status"),
]
