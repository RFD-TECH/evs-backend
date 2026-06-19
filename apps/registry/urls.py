"""EVS registry URL configuration."""
from django.urls import include, path
from rest_framework.routers import SimpleRouter

from . import views

router = SimpleRouter(trailing_slash=False)
router.register("credentials", views.CredentialViewSet, basename="credential")
router.register("batches", views.BatchIngestViewSet, basename="batch-ingest")
router.register("schemas", views.SchemaVersionViewSet, basename="schema-version")

urlpatterns = [
    path("", include(router.urls)),
    path("credentials/query", views.CredentialQueryView.as_view(), name="credential-query"),
]
