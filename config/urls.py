"""EVS master URL configuration."""
from django.urls import include, path
from rest_framework.response import Response
from rest_framework.views import APIView


class HealthView(APIView):
    """GET /health — liveness probe; no auth required."""

    authentication_classes = []
    permission_classes = []

    def get(self, request):
        return Response({"status": "ok", "service": "evs", "system": "03"})


def _make_schema_urls():
    try:
        from drf_spectacular.views import (
            SpectacularAPIView,
            SpectacularRedocView,
            SpectacularSwaggerView,
        )
        return [
            path("schema/", SpectacularAPIView.as_view(), name="schema"),
            path("schema/swagger-ui/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
            path("schema/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
        ]
    except ImportError:
        return []


urlpatterns = [
    path("health", HealthView.as_view(), name="health"),
    path("v1/verify/", include("apps.verification.urls")),
    path("v1/users/", include("apps.users.urls")),
    path("v1/registry/", include("apps.registry.urls")),
    path("v1/institutions/", include("apps.institutions.urls")),
    path("v1/audit/", include("apps.audit.urls")),
    path("v1/hsm/", include("apps.hsm.urls")),
    *_make_schema_urls(),
]
