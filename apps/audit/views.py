"""EVS audit query views — read-only, auditor role required."""
import logging

from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from shared.exceptions import error_response
from shared.pagination import StandardResultsPagination
from shared.permissions import check_permission

from .models import AuditEvent, DailyHashAnchor, SecurityEvent
from .serializers import (
    AuditEventDetailSerializer, AuditEventSerializer,
    DailyHashAnchorSerializer, SecurityEventSerializer,
)

logger = logging.getLogger(__name__)


class AuditEventViewSet(GenericViewSet):
    """Read-only audit trail. Requires audit:read permission."""

    pagination_class = StandardResultsPagination

    def get_queryset(self):
        return AuditEvent.objects.order_by("-id")

    def list(self, request):
        if not check_permission(request, "audit:read"):
            return error_response("Forbidden", status=403)

        qs = self.get_queryset()
        if action := request.query_params.get("action"):
            qs = qs.filter(action=action)
        if entity_type := request.query_params.get("entity_type"):
            qs = qs.filter(entity_type=entity_type)
        if entity_id := request.query_params.get("entity_id"):
            qs = qs.filter(entity_id=entity_id)
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
    """Security event log. Requires audit:read permission."""

    pagination_class = StandardResultsPagination

    def list(self, request):
        if not check_permission(request, "audit:read"):
            return error_response("Forbidden", status=403)

        qs = SecurityEvent.objects.order_by("-occurred_at")
        if category := request.query_params.get("category"):
            qs = qs.filter(category=category)
        if severity := request.query_params.get("severity"):
            qs = qs.filter(severity=severity)

        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(SecurityEventSerializer(page, many=True).data)
        return Response(SecurityEventSerializer(qs, many=True).data)


class DailyHashAnchorViewSet(GenericViewSet):
    """Daily hash anchors sent to System 22. Requires audit:read."""

    def list(self, request):
        if not check_permission(request, "audit:read"):
            return error_response("Forbidden", status=403)
        qs = DailyHashAnchor.objects.order_by("-date")
        return Response(DailyHashAnchorSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "audit:read"):
            return error_response("Forbidden", status=403)
        anchor = get_object_or_404(DailyHashAnchor, pk=pk)
        return Response(DailyHashAnchorSerializer(anchor).data)
