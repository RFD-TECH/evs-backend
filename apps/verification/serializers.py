"""EVS verification serializers — all channels."""
from rest_framework import serializers

from .models import (
    DocumentVaultObject, PdfSignatureOutcome,
    TrustAnchor, VerificationSession,
)


class VerificationSessionSerializer(serializers.ModelSerializer):
    credential_ref = serializers.SerializerMethodField()

    class Meta:
        model = VerificationSession
        fields = [
            "id", "channel", "credential_id_claimed", "credential_ref",
            "result", "result_detail", "verifier_ip", "verifier_user_agent",
            "verifier_id", "jwt_kid", "file_sha256", "verification_ms", "created_at",
        ]
        read_only_fields = fields

    def get_credential_ref(self, obj):
        return obj.credential.credential_ref if obj.credential else None


class TrustAnchorSerializer(serializers.ModelSerializer):
    class Meta:
        model = TrustAnchor
        fields = [
            "id", "ca_name", "ocsp_endpoint", "crl_endpoint",
            "status", "added_by", "added_at", "updated_at", "signed_change_ref",
        ]
        read_only_fields = ["id", "added_by", "added_at", "updated_at", "signed_change_ref"]


class TrustAnchorCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = TrustAnchor
        fields = ["ca_name", "ca_certificate_pem", "ocsp_endpoint", "crl_endpoint"]

    def validate_ca_certificate_pem(self, value):
        if not value.strip().startswith("-----BEGIN CERTIFICATE-----"):
            raise serializers.ValidationError("Value must be a PEM-encoded certificate.")
        return value


class DocumentVaultObjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = DocumentVaultObject
        fields = [
            "id", "sha256", "mime_type", "byte_size", "uploaded_by",
            "uploaded_at", "retention_until", "tamper_flag", "virus_clean",
        ]
        read_only_fields = fields
