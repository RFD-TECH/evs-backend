"""EVS registry serializers."""
from rest_framework import serializers

from .models import BatchIngest, Credential, CredentialSchemaVersion, RevocationRecord


class CredentialSchemaVersionSerializer(serializers.ModelSerializer):
    class Meta:
        model = CredentialSchemaVersion
        fields = [
            "id", "schema_id", "version", "label",
            "required_fields", "is_active", "created_at",
        ]
        read_only_fields = fields


class CredentialSerializer(serializers.ModelSerializer):
    schema_id = serializers.CharField(source="schema_version.schema_id", read_only=True)

    class Meta:
        model = Credential
        fields = [
            "id", "credential_ref", "schema_id", "institution_id",
            "graduation_cycle_id", "candidate_id",
            "sha256_hash", "qr_url", "status",
            "revoked_at", "revoke_reason",
            "integrity_checked_at", "integrity_ok",
            "created_at", "updated_at",
        ]
        read_only_fields = fields


class CredentialDetailSerializer(CredentialSerializer):
    """Includes full payload — only for credentialed roles."""

    class Meta(CredentialSerializer.Meta):
        fields = CredentialSerializer.Meta.fields + ["payload", "qr_payload"]
        read_only_fields = fields


class RevokeCredentialSerializer(serializers.Serializer):
    reason = serializers.CharField(min_length=10, max_length=1000)


class QuarantineCredentialSerializer(serializers.Serializer):
    reason = serializers.CharField(min_length=5, max_length=500)


class BatchIngestSerializer(serializers.ModelSerializer):
    class Meta:
        model = BatchIngest
        fields = [
            "id", "institution_id", "graduation_cycle_id",
            "original_filename", "file_hash", "file_format",
            "status", "total_records", "success_count", "failure_count",
            "row_errors", "created_at", "completed_at",
        ]
        read_only_fields = [
            "id", "file_hash", "status", "total_records",
            "success_count", "failure_count", "row_errors",
            "created_at", "completed_at",
        ]


class RevocationRecordSerializer(serializers.ModelSerializer):
    credential_ref = serializers.CharField(source="credential.credential_ref", read_only=True)

    class Meta:
        model = RevocationRecord
        fields = ["id", "credential_ref", "revoked_by", "reason", "revoked_at"]
        read_only_fields = fields
