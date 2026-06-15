"""EVS audit API views — Phase 9 & 10.

Includes:
  - Existing: AuditEventViewSet, SecurityEventViewSet, DailyHashAnchorViewSet
  - Phase 9:  DailyCommitmentViewSet, ExportRequestViewSet, RetentionTierLogViewSet,
              CommitmentVerifyView, SLODashboardView
  - Phase 10: GoLiveGateViewSet, DRDrillViewSet
"""
import logging
from datetime import date as date_cls, datetime

from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet

from shared.exceptions import error_response, success_response
from shared.pagination import StandardResultsPagination
from shared.permissions import check_permission

from .models import (
    AuditEvent, DailyCommitment, DailyHashAnchor, DRDrill,
    ExportRequest, GoLiveGate, RetentionTierLog, SecurityEvent,
)
from .serializers import (
    AuditEventDetailSerializer, AuditEventSerializer,
    CreateDRDrillSerializer, CreateExportRequestSerializer,
    DailyCommitmentSerializer, DailyHashAnchorSerializer,
    DRDrillSerializer, ExportRequestSerializer,
    GoLiveGateSerializer, GoLiveSignOffSerializer,
    RetentionTierLogSerializer, SecurityEventSerializer,
)

logger = logging.getLogger(__name__)

_EXPORT_RATE_LIMIT_PER_DAY = 5


# ── Existing ViewSets (unchanged) ─────────────────────────────────────────────


class AuditEventViewSet(GenericViewSet):
    """Read-only audit trail."""

    pagination_class = StandardResultsPagination
    serializer_class = AuditEventSerializer

    def get_queryset(self):
        return AuditEvent.objects.order_by("id")

    def list(self, request):
        if not check_permission(request, "audit:read"):
            return error_response("Forbidden", status=403)
        qs = self.get_queryset()
        if entity := request.query_params.get("entity_type"):
            qs = qs.filter(entity_type=entity)
        if actor := request.query_params.get("actor_id"):
            qs = qs.filter(actor_id=actor)
        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(AuditEventSerializer(page, many=True).data)
        return Response(AuditEventSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "audit:read"):
            return error_response("Forbidden", status=403)
        event = get_object_or_404(self.get_queryset(), pk=pk)
        return Response(AuditEventDetailSerializer(event).data)


class SecurityEventViewSet(GenericViewSet):
    """Read-only security event log."""

    pagination_class = StandardResultsPagination

    def get_queryset(self):
        return SecurityEvent.objects.order_by("-occurred_at")

    def list(self, request):
        if not check_permission(request, "audit:read"):
            return error_response("Forbidden", status=403)
        qs = self.get_queryset()
        if cat := request.query_params.get("category"):
            qs = qs.filter(category=cat)
        if sev := request.query_params.get("severity"):
            qs = qs.filter(severity=sev)
        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(SecurityEventSerializer(page, many=True).data)
        return Response(SecurityEventSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "audit:read"):
            return error_response("Forbidden", status=403)
        event = get_object_or_404(self.get_queryset(), pk=pk)
        return Response(SecurityEventSerializer(event).data)


class DailyHashAnchorViewSet(GenericViewSet):
    """Read-only daily hash anchor listing."""

    pagination_class = StandardResultsPagination

    def get_queryset(self):
        return DailyHashAnchor.objects.order_by("-date")

    def list(self, request):
        if not check_permission(request, "audit:read"):
            return error_response("Forbidden", status=403)
        page = self.paginate_queryset(self.get_queryset())
        if page is not None:
            return self.get_paginated_response(DailyHashAnchorSerializer(page, many=True).data)
        return Response(DailyHashAnchorSerializer(self.get_queryset(), many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "audit:read"):
            return error_response("Forbidden", status=403)
        anchor = get_object_or_404(self.get_queryset(), pk=pk)
        return Response(DailyHashAnchorSerializer(anchor).data)


# ── Phase 9 ViewSets ──────────────────────────────────────────────────────────


class DailyCommitmentViewSet(GenericViewSet):
    """Daily cryptographic commitment chain (Phase 9).

    GET  /v1/anchoring/commitments/           — list (paginated)
    GET  /v1/anchoring/commitments/{pk}/      — detail
    GET  /v1/anchoring/commitments/{pk}/verify/ — chain segment verification
    """

    pagination_class = StandardResultsPagination

    def get_queryset(self):
        return DailyCommitment.objects.select_related("anchor").order_by("-date")

    def list(self, request):
        if not check_permission(request, "audit:integrity"):
            return error_response("Forbidden", status=403)
        qs = self.get_queryset()
        if status := request.query_params.get("status"):
            qs = qs.filter(status=status)
        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(DailyCommitmentSerializer(page, many=True).data)
        return Response(DailyCommitmentSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "audit:integrity"):
            return error_response("Forbidden", status=403)
        commitment = get_object_or_404(self.get_queryset(), pk=pk)
        return Response(DailyCommitmentSerializer(commitment).data)

    @action(detail=True, methods=["get"])
    def verify(self, request, pk=None):
        """Verify this commitment's hash chain against its predecessor.

        Returns:
          - ``chain_valid``: True if commitment_hash matches computed value.
          - ``predecessor``: brief info on the prior commitment used in the check.
        """
        if not check_permission(request, "audit:integrity"):
            return error_response("Forbidden", status=403)

        import hashlib
        commitment = get_object_or_404(self.get_queryset(), pk=pk)
        head_hash = commitment.anchor.head_hash if commitment.anchor else ("0" * 64)
        raw = f"{commitment.prev_commitment_hash}{commitment.integrity_merkle_root}{head_hash}"
        expected = hashlib.sha256(raw.encode()).hexdigest()
        chain_valid = expected == commitment.commitment_hash

        predecessor = (
            DailyCommitment.objects.filter(date__lt=commitment.date)
            .order_by("-date")
            .values("date", "commitment_hash", "status")
            .first()
        )

        return success_response({
            "date": commitment.date.isoformat(),
            "chain_valid": chain_valid,
            "stored_hash": commitment.commitment_hash,
            "computed_hash": expected,
            "predecessor": predecessor,
        })


class ExportRequestViewSet(GenericViewSet):
    """Auditor-General signed export bundles (Phase 9 — EVS-N06).

    POST /v1/audit/exports/         — Submit (step-up MFA + audit:export perm)
    GET  /v1/audit/exports/         — List (actor sees own; admin sees all)
    GET  /v1/audit/exports/{id}/    — Detail + download URL
    """

    pagination_class = StandardResultsPagination

    def get_queryset(self):
        return ExportRequest.objects.order_by("-created_at")

    def _check_step_up(self, request) -> bool:
        """Return True if step-up MFA header is present."""
        from django.conf import settings
        header = getattr(settings, "STEP_UP_HEADER_MFA", "HTTP_X_MFA_VERIFIED")
        return request.META.get(header, "").lower() == "true"

    def list(self, request):
        if not check_permission(request, "audit:export"):
            return error_response("Forbidden", status=403)
        qs = self.get_queryset()
        # Non-admins see only their own requests
        if not check_permission(request, "audit:integrity"):
            actor = getattr(request.user, "id", None)
            qs = qs.filter(actor_id=actor)
        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(ExportRequestSerializer(page, many=True).data)
        return Response(ExportRequestSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "audit:export"):
            return error_response("Forbidden", status=403)
        req = get_object_or_404(self.get_queryset(), pk=pk)
        return Response(ExportRequestSerializer(req).data)

    def create(self, request):
        if not check_permission(request, "audit:export"):
            return error_response("Forbidden", status=403)

        # Step-up MFA required for signing
        if not self._check_step_up(request):
            return error_response(
                "Step-up MFA required. Include X-MFA-Verified: true header.", status=403
            )

        # Rate limit: max 5 per actor per day
        from django.conf import settings
        limit = getattr(settings, "EVS_EXPORT_RATE_LIMIT_PER_DAY", _EXPORT_RATE_LIMIT_PER_DAY)
        actor_id = getattr(request.user, "id", None)
        today_count = ExportRequest.objects.filter(
            actor_id=actor_id,
            created_at__date=timezone.now().date(),
        ).count()
        if today_count >= limit:
            return error_response(
                f"Daily export limit of {limit} reached. Try again tomorrow.", status=429
            )

        serializer = CreateExportRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)

        export_req = ExportRequest.objects.create(
            actor_id=actor_id,
            date_from=serializer.validated_data["date_from"],
            date_to=serializer.validated_data["date_to"],
            institution_id=serializer.validated_data.get("institution_id"),
        )

        from apps.audit.tasks import run_auditor_general_export
        run_auditor_general_export.apply_async(
            kwargs={"export_request_id": str(export_req.id)},
            queue="outbox",
        )

        return success_response(ExportRequestSerializer(export_req).data, status=202)


class RetentionTierLogViewSet(GenericViewSet):
    """Read-only retention tier migration log (Phase 9)."""

    pagination_class = StandardResultsPagination

    def get_queryset(self):
        return RetentionTierLog.objects.order_by("-run_date")

    def list(self, request):
        if not check_permission(request, "audit:integrity"):
            return error_response("Forbidden", status=403)
        qs = self.get_queryset()
        if t := request.query_params.get("tier_transition"):
            qs = qs.filter(tier_transition=t)
        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(RetentionTierLogSerializer(page, many=True).data)
        return Response(RetentionTierLogSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "audit:integrity"):
            return error_response("Forbidden", status=403)
        log = get_object_or_404(self.get_queryset(), pk=pk)
        return Response(RetentionTierLogSerializer(log).data)


class SLODashboardView(APIView):
    """GET /v1/ops/slo/dashboard — SLO metrics snapshot (Phase 9/10).

    Returns live metrics from the DB and cache:
    - Integrity sweep pass rate (last 30 days)
    - Credential count (active/revoked/quarantined)
    - Daily commitment status (last 7 days)
    - Recent export requests count
    """

    def get(self, request):
        if not check_permission(request, "audit:integrity"):
            return error_response("Forbidden", status=403)

        from datetime import timedelta
        from apps.registry.models import Credential, IntegrityRun

        cutoff_30d = timezone.now() - timedelta(days=30)
        cutoff_7d = timezone.now() - timedelta(days=7)

        # Integrity sweep stats
        recent_runs = list(
            IntegrityRun.objects.filter(started_at__gte=cutoff_30d)
            .values("status", "total_checked", "tampered_count", "sweep_type", "started_at")
            .order_by("-started_at")[:10]
        )
        completed_runs = [r for r in recent_runs if r["status"] == "completed"]
        sweep_pass_rate = (
            round(
                sum(1 for r in completed_runs if r["tampered_count"] == 0)
                / len(completed_runs) * 100,
                1,
            )
            if completed_runs
            else None
        )

        # Credential corpus stats
        cred_stats = {
            s: Credential.objects.filter(status=s).count()
            for s in [
                Credential.STATUS_ACTIVE,
                Credential.STATUS_REVOKED,
                Credential.STATUS_QUARANTINED,
            ]
        }

        # Daily commitment health (last 7 days)
        recent_commitments = list(
            DailyCommitment.objects.filter(created_at__gte=cutoff_7d)
            .values("date", "status", "commitment_hash")
            .order_by("-date")[:7]
        )

        # Export activity
        export_count_today = ExportRequest.objects.filter(
            created_at__date=timezone.now().date()
        ).count()

        return success_response({
            "slo": {
                "integrity_sweep_pass_rate_pct_30d": sweep_pass_rate,
                "recent_runs": recent_runs,
            },
            "credential_corpus": cred_stats,
            "daily_commitment_health_7d": recent_commitments,
            "exports_today": export_count_today,
            "generated_at": timezone.now().isoformat(),
        })


# ── Phase 10 ViewSets ─────────────────────────────────────────────────────────


class GoLiveGateViewSet(GenericViewSet):
    """Go-live readiness gate checklist (Phase 10).

    GET  /v1/programme/go-live-gates/               — list all gates + readiness summary
    GET  /v1/programme/go-live-gates/{id}/           — gate detail
    POST /v1/programme/go-live-gates/{id}/sign-off/  — sign off a gate (step-up required)
    """

    def get_queryset(self):
        return GoLiveGate.objects.order_by("display_order", "gate_id")

    def _check_step_up(self, request) -> bool:
        from django.conf import settings
        header = getattr(settings, "STEP_UP_HEADER_MFA", "HTTP_X_MFA_VERIFIED")
        return request.META.get(header, "").lower() == "true"

    def list(self, request):
        if not check_permission(request, "ops:go_live"):
            return error_response("Forbidden", status=403)
        qs = self.get_queryset()
        gates_data = GoLiveGateSerializer(qs, many=True).data
        return success_response({
            "gates": gates_data,
            "total": qs.count(),
            "signed_off": qs.filter(status=GoLiveGate.STATUS_SIGNED_OFF).count(),
            "all_ready": GoLiveGate.all_signed_off(),
        })

    def retrieve(self, request, pk=None):
        if not check_permission(request, "ops:go_live"):
            return error_response("Forbidden", status=403)
        gate = get_object_or_404(self.get_queryset(), pk=pk)
        return Response(GoLiveGateSerializer(gate).data)

    @action(detail=True, methods=["post"])
    def sign_off(self, request, pk=None):
        """Sign off a go-live gate. Requires step-up MFA and ops:go_live permission."""
        if not check_permission(request, "ops:go_live"):
            return error_response("Forbidden", status=403)
        if not self._check_step_up(request):
            return error_response(
                "Step-up MFA required. Include X-MFA-Verified: true header.", status=403
            )

        gate = get_object_or_404(self.get_queryset(), pk=pk)
        if gate.status == GoLiveGate.STATUS_SIGNED_OFF:
            return error_response("Gate is already signed off.", status=409)

        serializer = GoLiveSignOffSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)

        actor_id = getattr(request.user, "id", None)
        gate.status = GoLiveGate.STATUS_SIGNED_OFF
        gate.signed_off_by = actor_id
        gate.signed_off_at = timezone.now()
        gate.evidence = serializer.validated_data.get("evidence", {})
        gate.save(update_fields=["status", "signed_off_by", "signed_off_at", "evidence"])

        from apps.audit.models import AuditEvent
        AuditEvent.record(
            action="GO_LIVE_GATE_SIGNED_OFF",
            actor_id=actor_id,
            entity_type="GoLiveGate",
            entity_id=str(gate.pk),
            new_state={"gate_id": gate.gate_id, "all_ready": GoLiveGate.all_signed_off()},
        )

        return success_response({
            "gate": GoLiveGateSerializer(gate).data,
            "all_ready": GoLiveGate.all_signed_off(),
        })


class DRDrillViewSet(GenericViewSet):
    """Disaster Recovery drill records (Phase 10).

    GET  /v1/ops/dr-drills/       — list
    POST /v1/ops/dr-drills/       — create / record a drill result
    GET  /v1/ops/dr-drills/{id}/  — detail
    GET  /v1/ops/dr-drills/{id}/report/ — formatted drill report
    """

    pagination_class = StandardResultsPagination

    def get_queryset(self):
        return DRDrill.objects.order_by("-started_at")

    def list(self, request):
        if not check_permission(request, "ops:dr_drill"):
            return error_response("Forbidden", status=403)
        qs = self.get_queryset()
        if drill_type := request.query_params.get("drill_type"):
            qs = qs.filter(drill_type=drill_type)
        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(DRDrillSerializer(page, many=True).data)
        return Response(DRDrillSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "ops:dr_drill"):
            return error_response("Forbidden", status=403)
        drill = get_object_or_404(self.get_queryset(), pk=pk)
        return Response(DRDrillSerializer(drill).data)

    def create(self, request):
        if not check_permission(request, "ops:dr_drill"):
            return error_response("Forbidden", status=403)

        serializer = CreateDRDrillSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)

        d = serializer.validated_data
        actor_id = getattr(request.user, "id", None)
        drill = DRDrill.objects.create(
            drill_type=d["drill_type"],
            started_at=d["started_at"],
            completed_at=d.get("completed_at"),
            rto_seconds=d.get("rto_seconds"),
            rpo_seconds=d.get("rpo_seconds"),
            notes=d.get("notes", ""),
            triggered_by=actor_id,
        )

        # Auto-evaluate pass/fail if both RTO and RPO are provided
        if drill.rto_seconds is not None and drill.rpo_seconds is not None:
            drill.evaluate_pass()

        from apps.audit.models import AuditEvent
        AuditEvent.record(
            action="DR_DRILL_RECORDED",
            actor_id=actor_id,
            entity_type="DRDrill",
            entity_id=str(drill.id),
            new_state={
                "drill_type": drill.drill_type,
                "rto_seconds": drill.rto_seconds,
                "rpo_seconds": drill.rpo_seconds,
                "passed": drill.passed,
            },
        )

        return success_response(DRDrillSerializer(drill).data, status=201)

    @action(detail=True, methods=["get"])
    def report(self, request, pk=None):
        """Formatted drill report with NFR conformance analysis."""
        if not check_permission(request, "ops:dr_drill"):
            return error_response("Forbidden", status=403)

        drill = get_object_or_404(self.get_queryset(), pk=pk)

        conformance = {
            "rto": {
                "measured_seconds": drill.rto_seconds,
                "target_seconds": DRDrill.RTO_TARGET_SECONDS,
                "target_hours": DRDrill.RTO_TARGET_SECONDS / 3600,
                "meets_target": (
                    drill.rto_seconds <= DRDrill.RTO_TARGET_SECONDS
                    if drill.rto_seconds is not None
                    else None
                ),
            },
            "rpo": {
                "measured_seconds": drill.rpo_seconds,
                "target_seconds": DRDrill.RPO_TARGET_SECONDS,
                "target_hours": DRDrill.RPO_TARGET_SECONDS / 3600,
                "meets_target": (
                    drill.rpo_seconds <= DRDrill.RPO_TARGET_SECONDS
                    if drill.rpo_seconds is not None
                    else None
                ),
            },
            "overall_pass": drill.passed,
        }

        return success_response({
            "drill": DRDrillSerializer(drill).data,
            "nfr_conformance": conformance,
            "generated_at": timezone.now().isoformat(),
        })


# ── Cutover Runbook ───────────────────────────────────────────────────────────

_CUTOVER_RUNBOOK = [
    {
        "step": 1,
        "title": "Verify all Go-Live gates are signed off",
        "owner": "programme_manager",
        "completed": False,
    },
    {
        "step": 2,
        "title": "Enable read-only mode on legacy system",
        "owner": "system_administrator",
        "completed": False,
    },
    {
        "step": 3,
        "title": "Final data sync and integrity sweep",
        "owner": "system_administrator",
        "completed": False,
    },
    {
        "step": 4,
        "title": "DNS cutover — point evs.clet.gov.gh to production cluster",
        "owner": "programme_manager",
        "completed": False,
    },
    {
        "step": 5,
        "title": "Smoke test: verify a sample credential via QR and PDF",
        "owner": "registrar",
        "completed": False,
    },
    {
        "step": 6,
        "title": "Enable all production feature flags",
        "owner": "system_administrator",
        "completed": False,
    },
    {
        "step": 7,
        "title": "Monitor SLO dashboard for 30 minutes post-cutover",
        "owner": "system_administrator",
        "completed": False,
    },
    {
        "step": 8,
        "title": "Notify stakeholders — system is live",
        "owner": "programme_manager",
        "completed": False,
    },
]


class CutoverRunbookView(APIView):
    """GET /v1/programme/cutover/runbook/ — return the cutover runbook steps."""

    def get(self, request):
        if not check_permission(request, "ops:go_live"):
            return error_response("Forbidden", status=403)

        all_ready = GoLiveGate.all_signed_off()
        return success_response({
            "cutover_unlocked": all_ready,
            "steps": _CUTOVER_RUNBOOK,
            "gate_status": {
                "total": GoLiveGate.objects.count(),
                "signed_off": GoLiveGate.objects.filter(
                    status=GoLiveGate.STATUS_SIGNED_OFF
                ).count(),
            },
        })
