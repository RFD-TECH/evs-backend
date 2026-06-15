"""Serializers for legacy migration models (EVS-F09)."""
from __future__ import annotations

from rest_framework import serializers

from .models import (
    CredentialVersion,
    LegacyBatch,
    LegacyConfirmation,
    MigrationAuditReport,
    MigrationWave,
)


class MigrationWaveSerializer(serializers.ModelSerializer):
    class Meta:
        model = MigrationWave
        fields = [
            "id", "name", "description", "status", "institution_id",
            "graduation_year_from", "graduation_year_to", "confirmation_deadline",
            "activated_at", "activated_by", "went_live_at", "went_live_by",
            "rolled_back_at", "rolled_back_by", "rollback_reason",
            "quarantined_at", "quarantine_reason",
            "created_by", "created_at", "updated_at",
        ]
        read_only_fields = [
            "id", "status",
            "activated_at", "activated_by", "went_live_at", "went_live_by",
            "rolled_back_at", "rolled_back_by", "quarantined_at",
            "created_at", "updated_at",
        ]


class WaveRollbackSerializer(serializers.Serializer):
    reason = serializers.CharField(min_length=1, max_length=2000)


class WaveQuarantineSerializer(serializers.Serializer):
    reason = serializers.CharField(min_length=1, max_length=2000)


class LegacyBatchSerializer(serializers.ModelSerializer):
    class Meta:
        model = LegacyBatch
        fields = [
            "id", "wave", "batch_ref", "uploaded_by", "file_name",
            "file_sha256", "record_count", "ingested_count",
            "confirmed_count", "rejected_count",
            "status", "affidavit_ref", "affidavit_verified",
            "error_summary", "created_at", "updated_at",
        ]
        read_only_fields = [
            "id", "batch_ref", "uploaded_by", "ingested_count",
            "confirmed_count", "rejected_count",
            "status", "error_summary", "created_at", "updated_at",
        ]


class BatchIngestSerializer(serializers.Serializer):
    wave_id = serializers.UUIDField()
    file_name = serializers.CharField(max_length=500)
    file_sha256 = serializers.CharField(min_length=64, max_length=64)
    affidavit_ref = serializers.CharField(max_length=255)
    records = serializers.ListField(
        child=serializers.DictField(),
        min_length=1,
        max_length=5000,
    )

    def validate_records(self, value):
        if not value:
            raise serializers.ValidationError("records must not be empty.")
        return value


class AffidavitVerifySerializer(serializers.Serializer):
    verified = serializers.BooleanField()


class LegacyConfirmationSerializer(serializers.ModelSerializer):
    class Meta:
        model = LegacyConfirmation
        fields = [
            "id", "batch", "credential_id", "decision",
            "decided_by", "decided_at", "rejection_reason", "audit_hash",
        ]
        read_only_fields = ["id", "decided_by", "decided_at", "audit_hash"]


class ConfirmRecordSerializer(serializers.Serializer):
    credential_id = serializers.UUIDField()
    decision = serializers.ChoiceField(choices=[
        LegacyConfirmation.DECISION_CONFIRMED,
        LegacyConfirmation.DECISION_REJECTED,
    ])
    rejection_reason = serializers.CharField(required=False, allow_blank=True, max_length=2000)

    def validate(self, attrs):
        if attrs["decision"] == LegacyConfirmation.DECISION_REJECTED:
            if not attrs.get("rejection_reason", "").strip():
                raise serializers.ValidationError(
                    {"rejection_reason": "Required when decision is 'rejected'."}
                )
        return attrs


class CredentialVersionSerializer(serializers.ModelSerializer):
    class Meta:
        model = CredentialVersion
        fields = [
            "id", "credential_id", "version", "payload_snapshot",
            "sha256_at_version", "changed_by", "change_reason", "created_at",
        ]
        read_only_fields = fields


class RecordCorrectionSerializer(serializers.Serializer):
    patch = serializers.DictField(min_length=1)
    change_reason = serializers.CharField(min_length=1, max_length=500)


class MigrationAuditReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = MigrationAuditReport
        fields = [
            "id", "wave", "status", "report_payload",
            "admin_signer_id", "admin_signed_at", "admin_signature_hash",
            "registrar_signer_id", "registrar_signed_at", "registrar_signature_hash",
            "audit_chain_ref", "generated_at", "generated_by",
        ]
        read_only_fields = fields
