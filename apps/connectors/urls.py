"""Connectors URL configuration — Phase 5."""
from django.urls import include, path
from rest_framework.routers import SimpleRouter

from .views import ConnectorViewSet, ManualQueueViewSet, WaecVerificationView

router = SimpleRouter(trailing_slash=False)
router.register("connectors", ConnectorViewSet, basename="connector")
router.register("manual-queue", ManualQueueViewSet, basename="manual-queue")

urlpatterns = [
    path("verify/waec", WaecVerificationView.as_view(), name="verify-waec"),
    path("", include(router.urls)),
]
