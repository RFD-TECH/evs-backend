"""EVS verification URL configuration — QR scan channel (Phase 3)."""
from django.urls import include, path
from rest_framework.routers import SimpleRouter

from .views import PublicVerifyView, ResultRetrieveView, VerificationSessionViewSet

router = SimpleRouter(trailing_slash=False)
router.register("results", VerificationSessionViewSet, basename="verification-result")

urlpatterns = [
    path("<uuid:credential_id>", PublicVerifyView.as_view(), name="public-verify"),
    path("results/<uuid:result_id>", ResultRetrieveView.as_view(), name="verification-result-detail"),
    path("", include(router.urls)),
]
