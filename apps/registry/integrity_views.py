"""Registry integrity API views (Phase 9 — EVS-N05).

Endpoints:
  POST /v1/integrity/runs/manual    — Trigger an out-of-schedule integrity sweep
  GET  /v1/integrity/runs/          — List IntegrityRun records (paginated)
  GET  /v1/integrity/runs/{id}/     — Detail with checkpoint state and Merkle root
"""
import logging

from django.shortcuts import get_object_or_404
from rest_framework import serializers
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet

from shared.exceptions import error_response, success_response
from shared.pagination import StandardResultsPagination
from shared.permissions import check_permission

from .models import IntegrityRun

logger = logging.getLogger(__name__)


# ── Serializer ────────────────────────────────────────────────────────────────


class IntegrityRunSerializer(serializers.ModelSerializer):
    duration_seconds = serializers.SerializerMethodField()

    class Meta:
        model = IntegrityRun
        fields = [
            "id", "sweep_type", "started_at", "completed_at",
            "total_checked", "tampered_count",
            "merkle_root", "hsm_key_id",
            "status", "triggered_by",
            "error_detail", "duration_seconds",
        ]
        read_only_fields = fields

    def get_duration_seconds(self, obj):
        if obj.completed_at and obj.started_at:
            return round((obj.completed_at - obj.started_at).total_seconds(), 1)
        return None


# ── Views ─────────────────────────────────────────────────────────────────────


class IntegrityRunViewSet(GenericViewSet):
    """Integrity sweep run history and manual trigger."""

    pagination_class = StandardResultsPagination

    def get_queryset(self):
        return IntegrityRun.objects.order_by("-started_at")

    def list(self, request):
        if not check_permission(request, "audit:integrity"):
            return error_response("Forbidden", status=403)
        qs = self.get_queryset()
        if status := request.query_params.get("status"):
            qs = qs.filter(status=status)
        if sweep_type := request.query_params.get("sweep_type"):
            qs = qs.filter(sweep_type=sweep_type)
        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(IntegrityRunSerializer(page, many=True).data)
        return Response(IntegrityRunSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "audit:integrity"):
            return error_response("Forbidden", status=403)
        run = get_object_or_404(self.get_queryset(), pk=pk)
        return Response(IntegrityRunSerializer(run).data)

    @action(detail=False, methods=["post"], url_path="manual")
    def trigger_manual(self, request):
        """POST /v1/integrity/runs/manual — trigger an out-of-schedule sweep.

        Requires ``audit:integrity`` permission and no current ``running`` sweep.
        Returns the new ``IntegrityRun`` ID immediately; the sweep runs async.
        """
        if not check_permission(request, "audit:integrity"):
            return error_response("Forbidden", status=403)

        # Block if a sweep is already in progress
        if IntegrityRun.objects.filter(status=IntegrityRun.STATUS_RUNNING).exists():
            return error_response(
                "An integrity sweep is already running. Wait for it to complete.", status=409
            )

        actor_id = getattr(request.user, "id", None)

        from apps.registry.tasks import nightly_integrity_sweep
        result = nightly_integrity_sweep.apply_async(
            kwargs={
                "sweep_type": IntegrityRun.SWEEP_MANUAL,
                "triggered_by": str(actor_id) if actor_id else None,
            },
            queue="integrity-sweep",
        )

        # The task itself creates the IntegrityRun — fetch the newest running one
        import time
        time.sleep(0.2)   # brief wait for task to create the record
        run = IntegrityRun.objects.filter(
            sweep_type=IntegrityRun.SWEEP_MANUAL,
            status=IntegrityRun.STATUS_RUNNING,
        ).order_by("-started_at").first()

        return success_response(
            {"task_id": result.id, "run": IntegrityRunSerializer(run).data if run else None},
            status=202,
        )

    @action(detail=False, methods=["get"], url_path="latest")
    def latest(self, request):
        """GET /v1/integrity/runs/latest — most recent completed sweep."""
        if not check_permission(request, "audit:integrity"):
            return error_response("Forbidden", status=403)
        run = (
            IntegrityRun.objects.filter(status=IntegrityRun.STATUS_COMPLETED)
            .order_by("-completed_at")
            .first()
        )
        if not run:
            return success_response(None)
        return success_response(IntegrityRunSerializer(run).data)
