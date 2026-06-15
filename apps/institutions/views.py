"""EVS institutions API views."""
import logging

from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from shared.exceptions import error_response, success_response
from shared.pagination import StandardResultsPagination
from shared.permissions import check_permission

from .models import GraduationCycle, InstitutionMaster, SlaEvent
from .serializers import (
    GraduationCycleCreateSerializer, GraduationCycleSerializer,
    InstitutionCreateSerializer, InstitutionMasterSerializer, SlaEventSerializer,
)

logger = logging.getLogger(__name__)


class InstitutionViewSet(GenericViewSet):
    """Institution master CRUD. Registrar and system_administrator only."""

    pagination_class = StandardResultsPagination

    def get_queryset(self):
        return InstitutionMaster.objects.order_by("name")

    def list(self, request):
        if not check_permission(request, "institution:read"):
            return error_response("Forbidden", status=403)
        qs = self.get_queryset()
        if active := request.query_params.get("is_active"):
            qs = qs.filter(is_active=active.lower() in ("true", "1"))
        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(InstitutionMasterSerializer(page, many=True).data)
        return Response(InstitutionMasterSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "institution:read"):
            return error_response("Forbidden", status=403)
        inst = get_object_or_404(self.get_queryset(), pk=pk)
        return Response(InstitutionMasterSerializer(inst).data)

    def create(self, request):
        if not check_permission(request, "institution:manage"):
            return error_response("Forbidden", status=403)
        serializer = InstitutionCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)
        d = serializer.validated_data
        try:
            inst = InstitutionMaster.objects.create(
                name=d["name"],
                code=d["code"].upper(),
                accreditation_number=d.get("accreditation_number", ""),
                contact_email=d.get("contact_email", ""),
            )
        except Exception as exc:
            return error_response(str(exc), status=409)
        return success_response(InstitutionMasterSerializer(inst).data, status=201)

    def partial_update(self, request, pk=None):
        if not check_permission(request, "institution:manage"):
            return error_response("Forbidden", status=403)
        inst = get_object_or_404(self.get_queryset(), pk=pk)
        serializer = InstitutionMasterSerializer(inst, data=request.data, partial=True)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)
        serializer.save()
        return Response(InstitutionMasterSerializer(inst).data)

    @action(detail=True, methods=["post"])
    def deactivate(self, request, pk=None):
        if not check_permission(request, "institution:manage"):
            return error_response("Forbidden", status=403)
        inst = get_object_or_404(self.get_queryset(), pk=pk)
        inst.is_active = False
        inst.save(update_fields=["is_active", "updated_at"])
        return success_response({"is_active": False})


class GraduationCycleViewSet(GenericViewSet):
    """Graduation cycle lifecycle. Nested under /institutions/{institution_pk}/cycles/."""

    pagination_class = StandardResultsPagination

    def get_institution(self, institution_pk):
        return get_object_or_404(InstitutionMaster, pk=institution_pk)

    def get_queryset(self, institution):
        return GraduationCycle.objects.filter(institution=institution).order_by("-year")

    def list(self, request, institution_pk=None):
        if not check_permission(request, "institution:read"):
            return error_response("Forbidden", status=403)
        inst = self.get_institution(institution_pk)
        qs = self.get_queryset(inst)
        if st := request.query_params.get("status"):
            qs = qs.filter(status=st)
        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(GraduationCycleSerializer(page, many=True).data)
        return Response(GraduationCycleSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None, institution_pk=None):
        if not check_permission(request, "institution:read"):
            return error_response("Forbidden", status=403)
        inst = self.get_institution(institution_pk)
        cycle = get_object_or_404(GraduationCycle, pk=pk, institution=inst)
        return Response(GraduationCycleSerializer(cycle).data)

    def create(self, request, institution_pk=None):
        if not check_permission(request, "institution:manage"):
            return error_response("Forbidden", status=403)
        inst = self.get_institution(institution_pk)
        serializer = GraduationCycleCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)
        d = serializer.validated_data
        try:
            cycle = GraduationCycle.objects.create(
                institution=inst,
                year=d["year"],
                session=d.get("session", ""),
                submission_deadline=d["submission_deadline"],
            )
        except Exception as exc:
            return error_response(str(exc), status=409)
        return success_response(GraduationCycleSerializer(cycle).data, status=201)

    @action(detail=True, methods=["post"])
    def submit(self, request, pk=None, institution_pk=None):
        """Institution officer finalises their batch submission for this cycle."""
        if not check_permission(request, "bulk:ingest"):
            return error_response("Forbidden", status=403)
        inst = self.get_institution(institution_pk)
        cycle = get_object_or_404(GraduationCycle, pk=pk, institution=inst)
        if cycle.status != GraduationCycle.STATUS_OPEN:
            return error_response(
                f"Cycle is {cycle.status} — only open cycles can be submitted.", status=409
            )
        cycle.status = GraduationCycle.STATUS_SUBMITTED
        cycle.submitted_at = timezone.now()
        cycle.submitted_by = getattr(request.user, "id", None)
        cycle.save(update_fields=["status", "submitted_at", "submitted_by", "updated_at"])

        SlaEvent.objects.create(
            cycle=cycle,
            event_type=SlaEvent.EVENT_SUBMISSION_RECEIVED,
            details={"submitted_by": str(cycle.submitted_by)},
        )
        return success_response(GraduationCycleSerializer(cycle).data)

    @action(detail=True, methods=["get"], url_path="sla-events")
    def sla_events(self, request, pk=None, institution_pk=None):
        if not check_permission(request, "institution:read"):
            return error_response("Forbidden", status=403)
        inst = self.get_institution(institution_pk)
        cycle = get_object_or_404(GraduationCycle, pk=pk, institution=inst)
        events = SlaEvent.objects.filter(cycle=cycle).order_by("-occurred_at")
        return Response(SlaEventSerializer(events, many=True).data)
