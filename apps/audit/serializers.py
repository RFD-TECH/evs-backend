"""EVS audit serializers."""
from rest_framework import serializers

from .models import AuditEvent, DailyHashAnchor, SecurityEvent


class AuditEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditEvent
        fields = [
            "id", "event_id", "actor_id", "action",
            "entity_type", "entity_id",
            "ip_address", "request_id", "source_system",
            "chain_hash", "created_at",
        ]
        read_only_fields = fields


class AuditEventDetailSerializer(AuditEventSerializer):
    class Meta(AuditEventSerializer.Meta):
        fields = AuditEventSerializer.Meta.fields + ["old_state", "new_state", "user_agent"]
        read_only_fields = fields


class SecurityEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityEvent
        fields = [
            "id", "event_id", "category", "severity",
            "indicators", "ip_address", "actor_id",
            "request_id", "occurred_at",
        ]
        read_only_fields = fields


class DailyHashAnchorSerializer(serializers.ModelSerializer):
    class Meta:
        model = DailyHashAnchor
        fields = [
            "id", "date", "head_event_id", "head_hash",
            "event_count", "exported_to_s22_at", "anchor_ref", "created_at",
        ]
        read_only_fields = fields
