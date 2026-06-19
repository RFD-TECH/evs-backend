"""Connectors serializers — Phase 5."""
from rest_framework import serializers

from .models import (
    BreakerState, Connector, ConnectorCredential,
    ConnectorHealth, ManualQueueItem, WaecRequest,
)


class ConnectorSerializer(serializers.ModelSerializer):
    current_breaker_state = serializers.SerializerMethodField()

    class Meta:
        model = Connector
        fields = [
            "id", "name", "kind", "lifecycle_state", "contact_owner",
            "rate_limit_per_minute", "latency_p95_threshold_ms",
            "sandbox_validated_at", "created_at", "current_breaker_state",
        ]
        read_only_fields = fields

    def get_current_breaker_state(self, obj):
        from apps.connectors.circuit_breaker import get_current_state
        return get_current_state(obj)


class ConnectorPromoteSerializer(serializers.Serializer):
    production_endpoint = serializers.URLField()


class ConnectorSuspendSerializer(serializers.Serializer):
    reason = serializers.CharField(max_length=255)


class ConnectorCredentialSerializer(serializers.ModelSerializer):
    class Meta:
        model = ConnectorCredential
        fields = ["id", "kind", "valid_from", "valid_until", "rotation_reason", "created_at"]
        read_only_fields = fields


class ConnectorHealthSerializer(serializers.ModelSerializer):
    class Meta:
        model = ConnectorHealth
        fields = ["id", "ts", "probe_result", "latency_ms", "error_code"]
        read_only_fields = fields


class ManualQueueItemSerializer(serializers.ModelSerializer):
    connector_name = serializers.SerializerMethodField()
    sla_remaining_hours = serializers.SerializerMethodField()

    class Meta:
        model = ManualQueueItem
        fields = [
            "id", "connector_name", "consumer_id", "status",
            "queued_at", "sla_due_at", "sla_remaining_hours",
            "claimed_by", "claimed_at", "resolved_at",
            "resolution_status", "result_id", "attempt_count",
        ]
        read_only_fields = fields

    def get_connector_name(self, obj):
        return obj.connector.name if obj.connector else None

    def get_sla_remaining_hours(self, obj):
        from django.utils import timezone
        delta = obj.sla_due_at - timezone.now()
        return max(0, int(delta.total_seconds() / 3600))


class QueueResolveSerializer(serializers.Serializer):
    resolution_status = serializers.ChoiceField(choices=[
        "verified", "not_found", "mismatch", "rejected",
    ])
    justification = serializers.CharField(min_length=10, max_length=2000)


class WaecRequestSerializer(serializers.Serializer):
    index_number = serializers.RegexField(r"^[A-Za-z0-9]{5,20}$")
    year_of_completion = serializers.IntegerField(min_value=1990, max_value=2100)
    examination_series = serializers.ChoiceField(choices=["Private", "Regular"])
    date_of_birth = serializers.RegexField(
        r"^\d{2}/\d{2}/\d{4}$",
        error_messages={"invalid": "Use DD/MM/YYYY format."},
    )
