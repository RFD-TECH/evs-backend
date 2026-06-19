"""Foreign Credential Assessment URL configuration — Phase 6."""
from django.urls import include, path
from rest_framework.routers import SimpleRouter

from .views import ForeignCredentialApplicationViewSet

router = SimpleRouter(trailing_slash=False)
router.register("foreign-credentials", ForeignCredentialApplicationViewSet, basename="fca")

urlpatterns = [
    path("", include(router.urls)),
]
