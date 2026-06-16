"""EVS verification serializers — QR scan channel (Phase 3)."""
from rest_framework import serializers

from .models import VerificationSession


class VerificationSessionSerializer(serializers.ModelSerializer):
    credential_ref = serializers.SerializerMethodField()

    class Meta:
        model = VerificationSession
        fields = [
            "id", "result_id", "credential_id_claimed", "credential_ref",
            "result", "channel", "verifier_ip", "verifier_user_agent",
            "device_fingerprint", "verifier_id", "jwt_kid",
            "payload_hash", "checks_performed", "audit_chain_ref",
            "latency_ms", "created_at",
        ]
        read_only_fields = fields

    def get_credential_ref(self, obj):
        return obj.credential.credential_ref if obj.credential else None
