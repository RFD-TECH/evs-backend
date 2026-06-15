"""EVS verification serializers — QR scan channel (Phase 3)."""
from rest_framework import serializers

from .models import VerificationSession


class VerificationSessionSerializer(serializers.ModelSerializer):
    credential_ref = serializers.SerializerMethodField()

    class Meta:
        model = VerificationSession
        fields = [
            "id", "credential_id_claimed", "credential_ref",
            "result", "verifier_ip", "verifier_user_agent",
            "verifier_id", "jwt_kid", "verification_ms", "created_at",
        ]
        read_only_fields = fields

    def get_credential_ref(self, obj):
        return obj.credential.credential_ref if obj.credential else None
