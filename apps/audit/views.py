"""EVS audit query views — read-only, auditor role required."""
import hashlib
import json
import logging

from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework.response import Response
from rest_framework.views import APIView
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


class AuditExportView(APIView):
    """POST /v1/audit/exports

    Returns a DG-signed export of audit events for a given date range.
    The export_hash (SHA-256 of the canonical event list) is embedded in the
    signed JWT so recipients can verify data integrity without re-hashing.

    Requires: audit:read permission.
    Body: {"from_date": "YYYY-MM-DD", "to_date": "YYYY-MM-DD"}
    """

    def post(self, request):
        if not check_permission(request, "audit:read"):
            return error_response("Forbidden", status=403)

        from_date = request.data.get("from_date")
        to_date = request.data.get("to_date")
        if not from_date or not to_date:
            return error_response("'from_date' and 'to_date' are required.", status=400)

        try:
            from datetime import date
            from_date_obj = date.fromisoformat(from_date)
            to_date_obj = date.fromisoformat(to_date)
        except ValueError:
            return error_response("Dates must be ISO 8601 format (YYYY-MM-DD).", status=400)

        if from_date_obj > to_date_obj:
            return error_response("'from_date' must not be after 'to_date'.", status=400)

        from django.utils import timezone as tz
        start = tz.datetime(from_date_obj.year, from_date_obj.month, from_date_obj.day, tzinfo=tz.utc)
        end = tz.datetime(to_date_obj.year, to_date_obj.month, to_date_obj.day + 1
                          if to_date_obj.day < 28 else to_date_obj.month + 1, tzinfo=tz.utc)

        # Build end timestamp as start of the day AFTER to_date.
        from datetime import timedelta
        end = tz.datetime(to_date_obj.year, to_date_obj.month, to_date_obj.day, tzinfo=tz.utc) + timedelta(days=1)

        events_qs = AuditEvent.objects.filter(
            created_at__gte=start, created_at__lt=end
        ).order_by("id")

        events_data = AuditEventDetailSerializer(events_qs, many=True).data
        events_json = json.dumps(
            [dict(e) for e in events_data],
            sort_keys=True,
            default=str,
        )
        export_hash = hashlib.sha256(events_json.encode()).hexdigest()

        signed_at = timezone.now().isoformat()
        actor_sub = str((request.auth or {}).get("sub", ""))

        try:
            from apps.hsm.service import sign_payload
            signed = sign_payload(
                purpose="dg_sign",
                payload={
                    "export_hash": export_hash,
                    "from_date": from_date,
                    "to_date": to_date,
                    "event_count": len(events_data),
                    "exported_by": actor_sub,
                    "signed_at": signed_at,
                },
            )
            signature_token = signed.get("token")
            kid = signed.get("kid")
            algorithm = signed.get("algorithm")
        except Exception as exc:
            logger.error("audit_export.sign_failed err=%s", exc)
            return error_response("Export signing failed — check HSM configuration.", status=500)

        AuditEvent.record(
            action="AUDIT_EXPORT_CREATED",
            actor_id=actor_sub or None,
            entity_type="audit_export",
            entity_id=export_hash[:16],
            new_state={"from_date": from_date, "to_date": to_date, "event_count": len(events_data)},
            ip_address=getattr(request, "ip_address", None) or request.META.get("REMOTE_ADDR"),
            request_id=getattr(request, "request_id", None),
        )

        return Response({
            "from_date": from_date,
            "to_date": to_date,
            "event_count": len(events_data),
            "export_hash": export_hash,
            "events": events_data,
            "signature_token": signature_token,
            "kid": kid,
            "algorithm": algorithm,
            "signed_at": signed_at,
        })
