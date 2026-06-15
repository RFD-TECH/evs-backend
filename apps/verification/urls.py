"""EVS verification URL configuration — all channels."""
from django.urls import include, path
from rest_framework.routers import SimpleRouter

from .views import (
    DocumentVaultViewSet, PdfVerifyView, PublicVerifyView,
    TrustAnchorViewSet, UploadedQrVerifyView, VerificationSessionViewSet,
)

router = SimpleRouter(trailing_slash=False)
router.register("sessions", VerificationSessionViewSet, basename="verification-session")
router.register("trust-anchors", TrustAnchorViewSet, basename="trust-anchor")
router.register("vault", DocumentVaultViewSet, basename="vault")

urlpatterns = [
    path("<uuid:credential_id>", PublicVerifyView.as_view(), name="public-verify"),
    path("pdf", PdfVerifyView.as_view(), name="verify-pdf"),
    path("uploaded-qr", UploadedQrVerifyView.as_view(), name="verify-uploaded-qr"),
    path("", include(router.urls)),
]
