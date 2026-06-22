"""Legacy migration API views (EVS-F09)."""
from __future__ import annotations

import logging

from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from rest_framework.permissions import IsAuthenticated
from shared.pagination import StandardResultsPagination
from shared.permissions import HasPermission

from . import ingest_service, report_service, wave_service
from .models import (
    CredentialVersion,
    LegacyBatch,
    LegacyConfirmation,
    MigrationAuditReport,
    MigrationWave,
)
from .serializers import (
    AffidavitVerifySerializer,
    BatchIngestSerializer,
    ConfirmRecordSerializer,
    CredentialVersionSerializer,
    LegacyBatchSerializer,
    LegacyConfirmationSerializer,
    MigrationAuditReportSerializer,
    MigrationWaveSerializer,
    RecordCorrectionSerializer,
    WaveQuarantineSerializer,
    WaveRollbackSerializer,
)

logger = logging.getLogger(__name__)


def _actor(request):
    return getattr(request.user, "keycloak_sub", None) or str(request.user.pk)


# ── Migration waves ──────────────────────────────────────────────────────────

class MigrationWaveListCreateView(APIView):
    """GET/POST /v1/legacy/waves/"""

    def get_permissions(self):
        if self.request.method == "POST":
            return [IsAuthenticated(), HasPermission("legacy:manage")]
        return [IsAuthenticated(), HasPermission("legacy:manage")]

    def get(self, request):
        qs = MigrationWave.objects.all().order_by("-created_at")
        if inst := request.query_params.get("institution_id"):
            qs = qs.filter(institution_id=inst)
        if ws := request.query_params.get("status"):
            qs = qs.filter(status=ws)
        return Response(MigrationWaveSerializer(qs, many=True).data)

    def post(self, request):
        serializer = MigrationWaveSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        wave = serializer.save(created_by=_actor(request))
        return Response(MigrationWaveSerializer(wave).data, status=status.HTTP_201_CREATED)


class MigrationWaveDetailView(APIView):
    """GET/PATCH /v1/legacy/waves/{id}/"""

    permission_classes = [IsAuthenticated, HasPermission("legacy:manage")]

    def get(self, request, pk):
        wave = get_object_or_404(MigrationWave, pk=pk)
        return Response(MigrationWaveSerializer(wave).data)

    def patch(self, request, pk):
        wave = get_object_or_404(MigrationWave, pk=pk)
        if wave.status != MigrationWave.STATUS_PLANNED:
            return Response(
                {"detail": "Only Planned waves may be edited."},
                status=status.HTTP_409_CONFLICT,
            )
        serializer = MigrationWaveSerializer(wave, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class WaveActivateView(APIView):
    """POST /v1/legacy/waves/{id}/activate/"""

    permission_classes = [IsAuthenticated, HasPermission("legacy:manage")]

    def post(self, request, pk):
        wave = get_object_or_404(MigrationWave, pk=pk)
        wave = wave_service.activate_wave(wave, activated_by=_actor(request))
        return Response(MigrationWaveSerializer(wave).data)


class WaveGoLiveView(APIView):
    """POST /v1/legacy/waves/{id}/go-live/"""

    permission_classes = [IsAuthenticated, HasPermission("legacy:manage")]

    def post(self, request, pk):
        wave = get_object_or_404(MigrationWave, pk=pk)
        wave = wave_service.promote_to_live(wave, promoted_by=_actor(request))
        return Response(MigrationWaveSerializer(wave).data)


class WaveRollbackView(APIView):
    """POST /v1/legacy/waves/{id}/rollback/"""

    permission_classes = [IsAuthenticated, HasPermission("legacy:manage")]

    def post(self, request, pk):
        wave = get_object_or_404(MigrationWave, pk=pk)
        serializer = WaveRollbackSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        wave = wave_service.rollback_wave(
            wave, rolled_back_by=_actor(request), reason=serializer.validated_data["reason"]
        )
        return Response(MigrationWaveSerializer(wave).data)


class WaveQuarantineView(APIView):
    """POST /v1/legacy/waves/{id}/quarantine/"""

    permission_classes = [IsAuthenticated, HasPermission("legacy:manage")]

    def post(self, request, pk):
        wave = get_object_or_404(MigrationWave, pk=pk)
        serializer = WaveQuarantineSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        wave = wave_service.quarantine_wave(
            wave, quarantined_by=_actor(request), reason=serializer.validated_data["reason"]
        )
        return Response(MigrationWaveSerializer(wave).data)


# ── Batches ──────────────────────────────────────────────────────────────────

class LegacyBatchListView(APIView):
    """GET /v1/legacy/batches/"""

    permission_classes = [IsAuthenticated, HasPermission("legacy:manage")]

    def get(self, request):
        qs = LegacyBatch.objects.select_related("wave").order_by("-created_at")
        if wave_id := request.query_params.get("wave_id"):
            qs = qs.filter(wave_id=wave_id)
        return Response(LegacyBatchSerializer(qs, many=True).data)


class LegacyBatchIngestView(APIView):
    """POST /v1/legacy/batches/ingest/ — upload a batch of legacy records."""

    permission_classes = [IsAuthenticated, HasPermission("legacy:ingest")]

    def post(self, request):
        serializer = BatchIngestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        wave = get_object_or_404(MigrationWave, pk=data["wave_id"])

        batch = ingest_service.ingest_batch(
            wave=wave,
            records=data["records"],
            uploaded_by=_actor(request),
            file_name=data["file_name"],
            file_sha256=data["file_sha256"],
            affidavit_ref=data["affidavit_ref"],
        )
        return Response(LegacyBatchSerializer(batch).data, status=status.HTTP_201_CREATED)


class LegacyBatchDetailView(APIView):
    """GET /v1/legacy/batches/{id}/"""

    permission_classes = [IsAuthenticated, HasPermission("legacy:manage")]

    def get(self, request, pk):
        batch = get_object_or_404(LegacyBatch, pk=pk)
        return Response(LegacyBatchSerializer(batch).data)


class AffidavitVerifyView(APIView):
    """POST /v1/legacy/batches/{id}/verify-affidavit/"""

    permission_classes = [IsAuthenticated, HasPermission("legacy:manage")]

    def post(self, request, pk):
        batch = get_object_or_404(LegacyBatch, pk=pk)
        serializer = AffidavitVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        batch.affidavit_verified = serializer.validated_data["verified"]
        batch.save(update_fields=["affidavit_verified", "updated_at"])
        return Response(LegacyBatchSerializer(batch).data)


# ── Confirmations ─────────────────────────────────────────────────────────────

class ConfirmRecordView(APIView):
    """POST /v1/legacy/batches/{id}/confirm/ — confirm or reject one legacy record."""

    permission_classes = [IsAuthenticated, HasPermission("legacy:confirm")]

    def post(self, request, pk):
        batch = get_object_or_404(LegacyBatch, pk=pk)
        ingest_service.assert_affidavit_verified(batch)

        serializer = ConfirmRecordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        confirmation, created = LegacyConfirmation.objects.get_or_create(
            batch=batch,
            credential_id=data["credential_id"],
            defaults={
                "decision": data["decision"],
                "decided_by": _actor(request),
                "rejection_reason": data.get("rejection_reason", ""),
            },
        )
        if not created:
            return Response(
                {"detail": "This credential has already been confirmed/rejected in this batch."},
                status=status.HTTP_409_CONFLICT,
            )

        # Update batch counters
        if data["decision"] == LegacyConfirmation.DECISION_CONFIRMED:
            LegacyBatch.objects.filter(pk=batch.pk).update(
                confirmed_count=batch.confirmed_count + 1
            )
        else:
            LegacyBatch.objects.filter(pk=batch.pk).update(
                rejected_count=batch.rejected_count + 1
            )

        # Check if batch is fully confirmed
        batch.refresh_from_db()
        if batch.confirmed_count + batch.rejected_count >= batch.ingested_count:
            batch.status = LegacyBatch.STATUS_CONFIRMED
            batch.save(update_fields=["status", "updated_at"])

        return Response(LegacyConfirmationSerializer(confirmation).data, status=status.HTTP_201_CREATED)


# ── Record corrections ────────────────────────────────────────────────────────

class RecordCorrectionView(APIView):
    """POST /v1/legacy/records/{credential_id}/correct/"""

    permission_classes = [IsAuthenticated, HasPermission("legacy:manage")]

    def post(self, request, credential_id):
        serializer = RecordCorrectionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        credential = ingest_service.correct_record(
            credential_id=credential_id,
            patch=data["patch"],
            changed_by=_actor(request),
            change_reason=data["change_reason"],
        )
        return Response({"credential_id": str(credential.id), "status": "corrected"})


class CredentialVersionListView(APIView):
    """GET /v1/legacy/records/{credential_id}/versions/"""

    permission_classes = [IsAuthenticated, HasPermission("legacy:manage")]

    def get(self, request, credential_id):
        versions = CredentialVersion.objects.filter(
            credential_id=credential_id
        ).order_by("version")
        return Response(CredentialVersionSerializer(versions, many=True).data)


# ── Audit report ──────────────────────────────────────────────────────────────

class AuditReportView(APIView):
    """GET /v1/legacy/waves/{id}/audit-report/"""

    permission_classes = [IsAuthenticated, HasPermission("legacy:audit_report")]

    def get(self, request, pk):
        wave = get_object_or_404(MigrationWave, pk=pk)
        report = get_object_or_404(MigrationAuditReport, wave=wave)
        return Response(MigrationAuditReportSerializer(report).data)


class AuditReportGenerateView(APIView):
    """POST /v1/legacy/waves/{id}/audit-report/generate/"""

    permission_classes = [IsAuthenticated, HasPermission("legacy:audit_report")]

    def post(self, request, pk):
        wave = get_object_or_404(MigrationWave, pk=pk)
        report = report_service.generate_report(wave, generated_by=_actor(request))
        return Response(MigrationAuditReportSerializer(report).data, status=status.HTTP_201_CREATED)


class AuditReportSignAdminView(APIView):
    """POST /v1/legacy/waves/{id}/audit-report/sign-admin/"""

    permission_classes = [IsAuthenticated, HasPermission("legacy:manage")]

    def post(self, request, pk):
        wave = get_object_or_404(MigrationWave, pk=pk)
        report = get_object_or_404(MigrationAuditReport, wave=wave)
        report = report_service.sign_as_admin(report, signer_id=_actor(request))
        return Response(MigrationAuditReportSerializer(report).data)


class AuditReportSignRegistrarView(APIView):
    """POST /v1/legacy/waves/{id}/audit-report/sign-registrar/"""

    permission_classes = [IsAuthenticated, HasPermission("legacy:audit_report")]

    def post(self, request, pk):
        wave = get_object_or_404(MigrationWave, pk=pk)
        report = get_object_or_404(MigrationAuditReport, wave=wave)
        report = report_service.sign_as_registrar(report, signer_id=_actor(request))
        return Response(MigrationAuditReportSerializer(report).data)
