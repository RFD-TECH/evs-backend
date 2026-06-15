"""EVS verification URL configuration — QR scan channel (Phase 3)."""
from django.urls import include, path
from rest_framework.routers import SimpleRouter

from .views import PublicVerifyView, VerificationSessionViewSet

router = SimpleRouter(trailing_slash=False)
router.register("sessions", VerificationSessionViewSet, basename="verification-session")

urlpatterns = [
    path("<uuid:credential_id>", PublicVerifyView.as_view(), name="public-verify"),
    path("", include(router.urls)),
]
