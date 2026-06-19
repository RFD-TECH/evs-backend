"""EVS registry URL configuration."""
from django.urls import include, path
from rest_framework.routers import SimpleRouter

from . import views
from .integrity_views import IntegrityRunViewSet

router = SimpleRouter(trailing_slash=False)
router.register("credentials", views.CredentialViewSet, basename="credential")
router.register("batches", views.BatchIngestViewSet, basename="batch-ingest")
router.register("schemas", views.SchemaVersionViewSet, basename="schema-version")
# Phase 9 — integrity runs
router.register("integrity/runs", IntegrityRunViewSet, basename="integrity-run")

urlpatterns = [
    path("", include(router.urls)),
    path("credentials/query", views.CredentialQueryView.as_view(), name="credential-query"),
]
