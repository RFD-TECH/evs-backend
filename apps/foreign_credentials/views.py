"""Foreign Credential Assessment API views — Phase 6 (EVS-F03)."""
import logging

from django.shortcuts import get_object_or_404
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from shared.exceptions import error_response, success_response
from shared.pagination import StandardResultsPagination
from shared.permissions import check_permission

from .models import ForeignCredentialApplication
from .serializers import (
    ApplicationDocumentSerializer, AssignAssessorSerializer,
    DGDecisionSerializer, DGSignSerializer,
    EquivalenceRecommendationSerializer,
    ForeignCredentialApplicationSerializer, ForeignCredentialSubmitSerializer,
    RecommendationSerializer, RegistrarReviewSerializer,
    TriageSerializer, WorkflowTransitionSerializer,
)

logger = logging.getLogger(__name__)


class ForeignCredentialApplicationViewSet(GenericViewSet):
    """Full foreign-credential assessment lifecycle (Phase 6)."""

    pagination_class = StandardResultsPagination

    def get_queryset(self):
        return ForeignCredentialApplication.objects.order_by("-created_at")

    def list(self, request):
        if not check_permission(request, "foreign_credential:read"):
            return error_response("Forbidden", status=403)

        qs = self.get_queryset()
        if stage := request.query_params.get("stage"):
            qs = qs.filter(stage=stage)
        if route := request.query_params.get("route"):
            qs = qs.filter(route=route)
        if applicant := request.query_params.get("applicant_sub"):
            qs = qs.filter(applicant_sub=applicant)

        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(
                ForeignCredentialApplicationSerializer(page, many=True).data
            )
        return Response(ForeignCredentialApplicationSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "foreign_credential:read"):
            return error_response("Forbidden", status=403)
        app = get_object_or_404(self.get_queryset(), pk=pk)
        data = ForeignCredentialApplicationSerializer(app).data
        data["transitions"] = WorkflowTransitionSerializer(
            app.transitions.all(), many=True
        ).data
        data["documents"] = ApplicationDocumentSerializer(
            app.documents.all(), many=True
        ).data
        if hasattr(app, "dg_decision"):
            data["dg_decision"] = DGDecisionSerializer(app.dg_decision).data
        return Response(data)

    def create(self, request):
        """Applicant submits a foreign credential assessment application."""
        if not check_permission(request, "foreign_credential:apply"):
            return error_response("Forbidden", status=403)

        serializer = ForeignCredentialSubmitSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)

        from .workflow_service import submit_application
        app = submit_application(
            applicant_sub=str(getattr(request.user, "keycloak_sub", "")),
            **serializer.validated_data,
        )
        return success_response(ForeignCredentialApplicationSerializer(app).data)

    @action(detail=True, methods=["post"])
    def triage(self, request, pk=None):
        """Registrar routes the application to Internal Assessor or GTEC."""
        if not check_permission(request, "foreign_credential:triage"):
            return error_response("Forbidden", status=403)

        app = get_object_or_404(self.get_queryset(), pk=pk)
        serializer = TriageSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)

        from .workflow_service import triage
        try:
            triage(
                application=app,
                registrar_sub=str(getattr(request.user, "keycloak_sub", "")),
                **serializer.validated_data,
            )
        except ValueError as exc:
            return error_response(str(exc), status=409)
        return success_response(ForeignCredentialApplicationSerializer(app).data)

    @action(detail=True, methods=["post"], url_path="assign-assessor")
    def assign_assessor(self, request, pk=None):
        if not check_permission(request, "foreign_credential:triage"):
            return error_response("Forbidden", status=403)

        app = get_object_or_404(self.get_queryset(), pk=pk)
        serializer = AssignAssessorSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)

        from .workflow_service import assign_assessor
        try:
            assign_assessor(
                application=app,
                registrar_sub=str(getattr(request.user, "keycloak_sub", "")),
                **serializer.validated_data,
            )
        except ValueError as exc:
            return error_response(str(exc), status=409)
        return success_response(ForeignCredentialApplicationSerializer(app).data)

    @action(detail=True, methods=["post"])
    def recommend(self, request, pk=None):
        """Assessor submits their equivalence recommendation."""
        if not check_permission(request, "foreign_credential:assess"):
            return error_response("Forbidden", status=403)

        app = get_object_or_404(self.get_queryset(), pk=pk)
        serializer = RecommendationSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)

        from .workflow_service import submit_recommendation
        try:
            rec = submit_recommendation(
                application=app,
                assessor_sub=str(getattr(request.user, "keycloak_sub", "")),
                **serializer.validated_data,
            )
        except ValueError as exc:
            return error_response(str(exc), status=409)
        return success_response(EquivalenceRecommendationSerializer(rec).data)

    @action(detail=True, methods=["post"], url_path="registrar-review")
    def registrar_review(self, request, pk=None):
        if not check_permission(request, "foreign_credential:triage"):
            return error_response("Forbidden", status=403)

        app = get_object_or_404(self.get_queryset(), pk=pk)
        serializer = RegistrarReviewSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)

        from .workflow_service import registrar_review
        try:
            registrar_review(
                application=app,
                registrar_sub=str(getattr(request.user, "keycloak_sub", "")),
                notes=serializer.validated_data.get("notes", ""),
            )
        except ValueError as exc:
            return error_response(str(exc), status=409)
        return success_response(ForeignCredentialApplicationSerializer(app).data)

    @action(detail=True, methods=["post"], url_path="dg-sign")
    def dg_sign(self, request, pk=None):
        """Director-General digitally signs the final decision (HSM-backed key)."""
        if not check_permission(request, "foreign_credential:sign"):
            return error_response("Forbidden", status=403)

        app = get_object_or_404(self.get_queryset(), pk=pk)
        serializer = DGSignSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)

        from .workflow_service import dg_sign
        try:
            dg_sign(
                application=app,
                dg_sub=str(getattr(request.user, "keycloak_sub", "")),
                **serializer.validated_data,
            )
        except ValueError as exc:
            return error_response(str(exc), status=409)
        return success_response(ForeignCredentialApplicationSerializer(app).data)

    @action(detail=True, methods=["get"])
    def history(self, request, pk=None):
        """Full workflow transition history for an application."""
        if not check_permission(request, "foreign_credential:read"):
            return error_response("Forbidden", status=403)
        app = get_object_or_404(self.get_queryset(), pk=pk)
        return Response(WorkflowTransitionSerializer(app.transitions.all(), many=True).data)

    @action(detail=True, methods=["get"])
    def recommendations(self, request, pk=None):
        if not check_permission(request, "foreign_credential:read"):
            return error_response("Forbidden", status=403)
        app = get_object_or_404(self.get_queryset(), pk=pk)
        return Response(EquivalenceRecommendationSerializer(app.recommendations.all(), many=True).data)
