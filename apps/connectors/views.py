"""Connectors API views — Phase 5 (F04 + F08)."""
import logging

from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from shared.exceptions import error_response, success_response
from shared.pagination import StandardResultsPagination
from shared.permissions import check_permission

from .models import Connector, ConnectorHealth, ManualQueueItem
from .serializers import (
    ConnectorHealthSerializer, ConnectorPromoteSerializer,
    ConnectorSerializer, ConnectorSuspendSerializer,
    ManualQueueItemSerializer, QueueResolveSerializer,
    WaecRequestSerializer,
)

logger = logging.getLogger(__name__)


class ConnectorViewSet(GenericViewSet):
    """Connector lifecycle + health management (Administrator / DTI Operations)."""

    pagination_class = StandardResultsPagination

    def get_queryset(self):
        return Connector.objects.order_by("name")

    def list(self, request):
        if not check_permission(request, "connector:read"):
            return error_response("Forbidden", status=403)
        qs = self.get_queryset()
        if kind := request.query_params.get("kind"):
            qs = qs.filter(kind=kind)
        if state := request.query_params.get("lifecycle_state"):
            qs = qs.filter(lifecycle_state=state)
        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(ConnectorSerializer(page, many=True).data)
        return Response(ConnectorSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "connector:read"):
            return error_response("Forbidden", status=403)
        return Response(ConnectorSerializer(get_object_or_404(self.get_queryset(), pk=pk)).data)

    @action(detail=True, methods=["post"])
    def promote(self, request, pk=None):
        """Promote connector from sandbox_validated → production_live.

        Requires sandbox validation to have run within the last 24 hours.
        """
        if not check_permission(request, "connector:manage"):
            return error_response("Forbidden", status=403)

        connector = get_object_or_404(self.get_queryset(), pk=pk)
        if connector.lifecycle_state != Connector.LIFECYCLE_SANDBOX:
            return error_response(
                "Only sandbox_validated connectors can be promoted.", status=409
            )

        from datetime import timedelta
        if not connector.sandbox_validated_at or (
            timezone.now() - connector.sandbox_validated_at > timedelta(hours=24)
        ):
            return error_response(
                "Sandbox validation must have run within the last 24 hours.", status=409
            )

        serializer = ConnectorPromoteSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)

        connector.lifecycle_state = Connector.LIFECYCLE_LIVE
        connector.production_endpoint = serializer.validated_data["production_endpoint"]
        connector.save(update_fields=["lifecycle_state", "production_endpoint", "updated_at"])
        _audit_connector("CONNECTOR_PROMOTED", connector, request)
        return success_response(ConnectorSerializer(connector).data)

    @action(detail=True, methods=["post"])
    def suspend(self, request, pk=None):
        if not check_permission(request, "connector:manage"):
            return error_response("Forbidden", status=403)

        connector = get_object_or_404(self.get_queryset(), pk=pk)
        serializer = ConnectorSuspendSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)

        connector.lifecycle_state = Connector.LIFECYCLE_SUSPENDED
        connector.save(update_fields=["lifecycle_state", "updated_at"])
        _audit_connector("CONNECTOR_SUSPENDED", connector, request,
                         extra={"reason": serializer.validated_data["reason"]})
        return success_response(ConnectorSerializer(connector).data)

    @action(detail=True, methods=["get"])
    def health(self, request, pk=None):
        if not check_permission(request, "connector:read"):
            return error_response("Forbidden", status=403)
        connector = get_object_or_404(self.get_queryset(), pk=pk)
        recent = ConnectorHealth.objects.filter(connector=connector).order_by("-ts")[:50]
        return Response({
            "connector": ConnectorSerializer(connector).data,
            "recent_probes": ConnectorHealthSerializer(recent, many=True).data,
        })


class WaecVerifyView:
    """POST /v1/verify/waec — WAEC verification endpoint (F08).

    Implemented as a function-based endpoint, mounted in connectors/urls.py.
    """
    pass


class ManualQueueViewSet(GenericViewSet):
    """Manual verification queue management (Registrar — F04-04)."""

    pagination_class = StandardResultsPagination

    def get_queryset(self):
        return ManualQueueItem.objects.order_by("sla_due_at")

    def list(self, request):
        if not check_permission(request, "queue:manage"):
            return error_response("Forbidden", status=403)

        qs = self.get_queryset()
        if status := request.query_params.get("status"):
            qs = qs.filter(status=status)
        if connector := request.query_params.get("connector"):
            qs = qs.filter(connector__name__icontains=connector)

        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(ManualQueueItemSerializer(page, many=True).data)
        return Response(ManualQueueItemSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "queue:manage"):
            return error_response("Forbidden", status=403)
        item = get_object_or_404(self.get_queryset(), pk=pk)
        return Response(ManualQueueItemSerializer(item).data)

    @action(detail=True, methods=["post"])
    def claim(self, request, pk=None):
        if not check_permission(request, "queue:manage"):
            return error_response("Forbidden", status=403)
        item = get_object_or_404(self.get_queryset(), pk=pk)
        if item.status != ManualQueueItem.STATUS_PENDING:
            return error_response("Item is not in pending status.", status=409)
        item.status = ManualQueueItem.STATUS_CLAIMED
        item.claimed_by = getattr(request.user, "keycloak_sub", None)
        item.claimed_at = timezone.now()
        item.save(update_fields=["status", "claimed_by", "claimed_at"])
        return success_response(ManualQueueItemSerializer(item).data)

    @action(detail=True, methods=["post"])
    def resolve(self, request, pk=None):
        if not check_permission(request, "queue:manage"):
            return error_response("Forbidden", status=403)
        item = get_object_or_404(self.get_queryset(), pk=pk)
        if item.status not in (ManualQueueItem.STATUS_PENDING, ManualQueueItem.STATUS_CLAIMED):
            return error_response("Item is already resolved or escalated.", status=409)

        serializer = QueueResolveSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)

        import uuid
        item.status = ManualQueueItem.STATUS_RESOLVED
        item.resolved_at = timezone.now()
        item.resolution_status = serializer.validated_data["resolution_status"]
        item.justification = serializer.validated_data["justification"]
        item.result_id = uuid.uuid4()
        item.save(update_fields=[
            "status", "resolved_at", "resolution_status", "justification", "result_id"
        ])
        _audit_queue("MANUAL_QUEUE_RESOLVED", item, request)
        return success_response(ManualQueueItemSerializer(item).data)


# ── WAEC standalone view ──────────────────────────────────────────────────────

from rest_framework.views import APIView


class WaecVerificationView(APIView):
    """POST /v1/verify/waec"""

    def post(self, request):
        if not check_permission(request, "verification:waec"):
            return error_response("Forbidden", status=403)

        serializer = WaecRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)

        d = serializer.validated_data
        from apps.connectors.waec_service import verify_waec
        result = verify_waec(
            index_number=d["index_number"],
            year_of_completion=d["year_of_completion"],
            examination_series=d["examination_series"],
            date_of_birth=d["date_of_birth"],
            verifier_id=getattr(request.user, "keycloak_sub", None),
            ip=_get_client_ip(request),
        )
        http_status = 200 if result["result"] in ("verified",) else (
            503 if result["result"] == "manual_pending" else 400
        )
        return Response(result, status=http_status)


def _get_client_ip(request) -> str:
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def _audit_connector(action: str, connector, request, extra: dict | None = None):
    try:
        from apps.audit.models import AuditEvent
        AuditEvent.record(
            action=action,
            entity_type="Connector",
            entity_id=str(connector.id),
            actor_id=getattr(request.user, "keycloak_sub", None),
            new_state={"connector": connector.name, "state": connector.lifecycle_state, **(extra or {})},
            old_state={},
        )
    except Exception:
        pass


def _audit_queue(action: str, item, request):
    try:
        from apps.audit.models import AuditEvent
        AuditEvent.record(
            action=action,
            entity_type="ManualQueueItem",
            entity_id=str(item.id),
            actor_id=getattr(request.user, "keycloak_sub", None),
            new_state={"status": item.status, "resolution": item.resolution_status},
            old_state={},
        )
    except Exception:
        pass
