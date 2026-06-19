"""EVS audit URL configuration."""
from django.urls import include, path
from rest_framework.routers import SimpleRouter

from .views import AuditEventViewSet, AuditExportView, DailyHashAnchorViewSet, SecurityEventViewSet

router = SimpleRouter(trailing_slash=False)
router.register("events", AuditEventViewSet, basename="audit-event")
router.register("security-events", SecurityEventViewSet, basename="security-event")
router.register("anchors", DailyHashAnchorViewSet, basename="hash-anchor")

urlpatterns = [
    path("", include(router.urls)),
    path("exports", AuditExportView.as_view(), name="audit-export"),
]
