"""Fraud detection API views (EVS-F05)."""
from __future__ import annotations

import logging

from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ReadOnlyModelViewSet

from rest_framework.permissions import IsAuthenticated
from shared.pagination import StandardResultsPagination
from shared.permissions import HasPermission

from . import detection_service, evidence_service
from .models import FraudFlag, RuleDefinition, RuleRun, WatchlistEntry
from .serializers import (
    FlagAddendumSerializer,
    FlagResolutionSerializer,
    FraudFlagSerializer,
    FraudRunRequestSerializer,
    RuleDefinitionActivateSerializer,
    RuleDefinitionSerializer,
    RuleDryRunSerializer,
    RuleRunSerializer,
    WatchlistClearSerializer,
    WatchlistEntrySerializer,
)

logger = logging.getLogger(__name__)


def _actor(request):
    return getattr(request.user, "keycloak_sub", None) or str(request.user.pk)


# ── Detection run ────────────────────────────────────────────────────────────

class FraudRunView(APIView):
    """POST /v1/fraud/runs/ — trigger an on-demand detection run."""

    permission_classes = [IsAuthenticated, HasPermission("fraud:run")]

    def post(self, request):
        serializer = FraudRunRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        run = detection_service.run_detection(
            trigger=data["trigger"],
            triggered_by=_actor(request),
            batch_id=data.get("batch_id"),
            fuzzy_threshold=data.get("fuzzy_threshold", 0.85),
        )
        return Response(RuleRunSerializer(run).data, status=status.HTTP_201_CREATED)


class FraudRunDetailView(APIView):
    """GET /v1/fraud/runs/{id}/"""

    permission_classes = [IsAuthenticated, HasPermission("fraud:read")]

    def get(self, request, pk):
        run = get_object_or_404(RuleRun, pk=pk)
        return Response(RuleRunSerializer(run).data)


# ── Fraud flags ──────────────────────────────────────────────────────────────

class FraudFlagViewSet(ReadOnlyModelViewSet):
    """GET /v1/fraud/flags/ and /v1/fraud/flags/{id}/"""

    permission_classes = [IsAuthenticated, HasPermission("fraud:read")]
    serializer_class = FraudFlagSerializer
    pagination_class = StandardResultsPagination

    def get_queryset(self):
        qs = FraudFlag.objects.select_related("rule", "run").prefetch_related("actions")
        params = self.request.query_params
        if severity := params.get("severity"):
            qs = qs.filter(severity=severity)
        if flag_status := params.get("status"):
            qs = qs.filter(status=flag_status)
        if flag_type := params.get("flag_type"):
            qs = qs.filter(flag_type=flag_type)
        return qs.order_by("-created_at")


class FlagEvidenceView(APIView):
    """GET /v1/fraud/flags/{id}/evidence/ — assemble the evidence package."""

    permission_classes = [IsAuthenticated, HasPermission("fraud:investigate")]

    def get(self, request, pk):
        flag = get_object_or_404(FraudFlag, pk=pk)
        package = evidence_service.assemble_evidence(flag, actor_id=_actor(request))
        return Response(package)


class FlagResolveView(APIView):
    """POST /v1/fraud/flags/{id}/resolve/ — resolve a flag."""

    permission_classes = [IsAuthenticated, HasPermission("fraud:investigate")]

    def post(self, request, pk):
        flag = get_object_or_404(FraudFlag, pk=pk)
        serializer = FlagResolutionSerializer(
            data=request.data, context={"flag": flag}
        )
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        flag = detection_service.resolve_flag(
            flag=flag,
            new_status=data["new_status"],
            justification=data["justification"],
            resolver_id=_actor(request),
        )
        return Response(FraudFlagSerializer(flag).data)


class FlagAddendumView(APIView):
    """POST /v1/fraud/flags/{id}/addendum/ — attach an addendum."""

    permission_classes = [IsAuthenticated, HasPermission("fraud:investigate")]

    def post(self, request, pk):
        flag = get_object_or_404(FraudFlag, pk=pk)
        serializer = FlagAddendumSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        action = evidence_service.add_addendum(
            flag=flag,
            actor_id=_actor(request),
            note=data["note"],
            additional_evidence=data.get("additional_evidence"),
        )
        return Response({"id": str(action.id), "action": action.action}, status=status.HTTP_201_CREATED)


# ── Rule definitions ─────────────────────────────────────────────────────────

class RuleDefinitionListCreateView(APIView):
    """GET /v1/fraud/rules/ and POST /v1/fraud/rules/"""

    def get_permissions(self):
        if self.request.method == "POST":
            return [IsAuthenticated(), HasPermission("fraud:manage_rules")]
        return [IsAuthenticated(), HasPermission("fraud:read")]

    def get(self, request):
        qs = RuleDefinition.objects.all().order_by("name", "-version")
        serializer = RuleDefinitionSerializer(qs, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = RuleDefinitionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        rule = serializer.save(created_by=_actor(request))
        return Response(RuleDefinitionSerializer(rule).data, status=status.HTTP_201_CREATED)


class RuleDefinitionDetailView(APIView):
    """GET/PATCH /v1/fraud/rules/{id}/"""

    def get_permissions(self):
        if self.request.method == "PATCH":
            return [IsAuthenticated(), HasPermission("fraud:manage_rules")]
        return [IsAuthenticated(), HasPermission("fraud:read")]

    def get(self, request, pk):
        rule = get_object_or_404(RuleDefinition, pk=pk)
        return Response(RuleDefinitionSerializer(rule).data)

    def patch(self, request, pk):
        rule = get_object_or_404(RuleDefinition, pk=pk)
        if rule.enabled:
            return Response(
                {"detail": "Cannot edit an enabled rule. Deprecate it and create a new version."},
                status=status.HTTP_409_CONFLICT,
            )
        serializer = RuleDefinitionSerializer(rule, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        rule = serializer.save(version=rule.version + 1)
        return Response(RuleDefinitionSerializer(rule).data)


class RuleApproveView(APIView):
    """POST /v1/fraud/rules/{id}/approve/ — first-leg dual-control approval."""

    permission_classes = [IsAuthenticated, HasPermission("fraud:manage_rules")]

    def post(self, request, pk):
        rule = get_object_or_404(RuleDefinition, pk=pk)
        actor = _actor(request)

        if str(actor) == str(rule.created_by):
            return Response(
                {"detail": "First approver may not be the rule author."},
                status=status.HTTP_403_FORBIDDEN,
            )
        if rule.approved_by:
            return Response(
                {"detail": "Rule already has a first approval."},
                status=status.HTTP_409_CONFLICT,
            )

        rule.approved_by = actor
        rule.save(update_fields=["approved_by", "updated_at"])
        return Response(RuleDefinitionSerializer(rule).data)


class RuleActivateView(APIView):
    """POST /v1/fraud/rules/{id}/activate/ — second-leg dual-control activation."""

    permission_classes = [IsAuthenticated, HasPermission("fraud:manage_rules")]

    def post(self, request, pk):
        rule = get_object_or_404(RuleDefinition, pk=pk)
        serializer = RuleDefinitionActivateSerializer(
            data=request.data,
            context={"rule": rule, "request_user_id": _actor(request)},
        )
        serializer.is_valid(raise_exception=True)

        rule.second_approver = serializer.validated_data["approver_id"]
        rule.enabled = True
        rule.effective_from = rule.effective_from or timezone.now()
        rule.save(update_fields=["second_approver", "enabled", "effective_from", "updated_at"])
        return Response(RuleDefinitionSerializer(rule).data)


class RuleDeprecateView(APIView):
    """POST /v1/fraud/rules/{id}/deprecate/"""

    permission_classes = [IsAuthenticated, HasPermission("fraud:manage_rules")]

    def post(self, request, pk):
        rule = get_object_or_404(RuleDefinition, pk=pk)
        if rule.deprecated_at:
            return Response({"detail": "Rule is already deprecated."}, status=status.HTTP_409_CONFLICT)
        rule.deprecated_at = timezone.now()
        rule.enabled = False
        rule.save(update_fields=["deprecated_at", "enabled", "updated_at"])
        return Response(RuleDefinitionSerializer(rule).data)


class RuleDryRunView(APIView):
    """POST /v1/fraud/rules/dry-run/ — test predicate against sample records."""

    permission_classes = [IsAuthenticated, HasPermission("fraud:manage_rules")]

    def post(self, request):
        from apps.registry.models import Credential

        serializer = RuleDryRunSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        predicate = data["predicate_json"]
        credential_ids = data.get("credential_ids")

        qs = Credential.objects.filter(status=Credential.STATUS_ACTIVE)
        if credential_ids:
            qs = qs.filter(pk__in=credential_ids)
        else:
            qs = qs.order_by("?")[:200]

        sample = [{"id": str(c.id), "credential_ref": c.credential_ref, "payload": c.payload or {}}
                  for c in qs]
        result = detection_service._engine.dry_run(predicate, sample)
        return Response(result)


# ── Watchlist ────────────────────────────────────────────────────────────────

class WatchlistView(APIView):
    """GET /v1/fraud/watchlist/"""

    permission_classes = [IsAuthenticated, HasPermission("watchlist:read")]

    def get(self, request):
        qs = WatchlistEntry.objects.select_related("reason_flag")
        if applicant_id := request.query_params.get("applicant_id"):
            qs = qs.filter(applicant_id=applicant_id)
        if ws_status := request.query_params.get("status"):
            qs = qs.filter(status=ws_status)
        serializer = WatchlistEntrySerializer(qs.order_by("-added_at"), many=True)
        return Response(serializer.data)


class WatchlistClearView(APIView):
    """POST /v1/fraud/watchlist/{id}/clear/ — clear a watchlist entry."""

    permission_classes = [IsAuthenticated, HasPermission("fraud:investigate")]

    def post(self, request, pk):
        entry = get_object_or_404(WatchlistEntry, pk=pk)
        if entry.status == WatchlistEntry.STATUS_CLEARED:
            return Response({"detail": "Entry already cleared."}, status=status.HTTP_409_CONFLICT)

        serializer = WatchlistClearSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        entry.status = WatchlistEntry.STATUS_CLEARED
        entry.cleared_at = timezone.now()
        entry.cleared_reason = serializer.validated_data["cleared_reason"]
        entry.save()
        return Response(WatchlistEntrySerializer(entry).data)
