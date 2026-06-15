"""EVS audit URL configuration — Phase 9 & 10."""
from django.urls import include, path
from rest_framework.routers import SimpleRouter

from .views import (
    AuditEventViewSet, DailyHashAnchorViewSet, SecurityEventViewSet,
    # Phase 9
    DailyCommitmentViewSet, ExportRequestViewSet, RetentionTierLogViewSet,
    SLODashboardView,
    # Phase 10
    GoLiveGateViewSet, DRDrillViewSet, CutoverRunbookView,
)

router = SimpleRouter(trailing_slash=False)

# Existing
router.register("events", AuditEventViewSet, basename="audit-event")
router.register("security-events", SecurityEventViewSet, basename="security-event")
router.register("anchors", DailyHashAnchorViewSet, basename="hash-anchor")

# Phase 9
router.register("anchoring/commitments", DailyCommitmentViewSet, basename="daily-commitment")
router.register("audit/exports", ExportRequestViewSet, basename="export-request")
router.register("audit/retention-logs", RetentionTierLogViewSet, basename="retention-tier-log")

# Phase 10
router.register("programme/go-live-gates", GoLiveGateViewSet, basename="go-live-gate")
router.register("ops/dr-drills", DRDrillViewSet, basename="dr-drill")

urlpatterns = [
    path("", include(router.urls)),
    # Phase 9 — SLO dashboard
    path("ops/slo/dashboard", SLODashboardView.as_view(), name="slo-dashboard"),
    # Phase 10 — Cutover runbook
    path("programme/cutover/runbook", CutoverRunbookView.as_view(), name="cutover-runbook"),
]
