"""EVS audit serializers."""
from rest_framework import serializers

from .models import (
    AuditEvent, DailyHashAnchor, SecurityEvent,
    DailyCommitment, ExportRequest, RetentionTierLog,
    GoLiveGate, DRDrill,
)


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


# ── Phase 9 Serializers ────────────────────────────────────────────────────────


class DailyCommitmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = DailyCommitment
        fields = [
            "id", "date", "integrity_merkle_root",
            "prev_commitment_hash", "commitment_hash",
            "hsm_key_id", "s22_receipt",
            "submitted_to_s22_at", "status", "retry_count", "created_at",
        ]
        read_only_fields = fields


class ExportRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExportRequest
        fields = [
            "id", "actor_id", "date_from", "date_to", "institution_id",
            "status", "bundle_hash", "hsm_key_id",
            "signed_bundle_url", "signed_at", "created_at",
        ]
        read_only_fields = [
            "id", "actor_id", "status", "bundle_hash", "hsm_key_id",
            "signed_bundle_url", "signed_at", "created_at",
        ]


class CreateExportRequestSerializer(serializers.Serializer):
    date_from = serializers.DateField()
    date_to = serializers.DateField()
    institution_id = serializers.UUIDField(required=False, allow_null=True)

    def validate(self, data):
        if data["date_from"] > data["date_to"]:
            raise serializers.ValidationError("date_from must be before date_to.")
        max_range = 366
        if (data["date_to"] - data["date_from"]).days > max_range:
            raise serializers.ValidationError(
                f"Export range cannot exceed {max_range} days."
            )
        return data


class RetentionTierLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = RetentionTierLog
        fields = [
            "id", "tier_transition", "run_date", "event_count",
            "manifest_hash", "hsm_key_id", "archive_path",
            "status", "created_at", "completed_at",
        ]
        read_only_fields = fields


# ── Phase 10 Serializers ───────────────────────────────────────────────────────


class GoLiveGateSerializer(serializers.ModelSerializer):
    class Meta:
        model = GoLiveGate
        fields = [
            "id", "gate_id", "title", "description", "owner_role",
            "status", "signed_off_by", "signed_off_at", "evidence",
            "display_order", "created_at",
        ]
        read_only_fields = [
            "id", "status", "signed_off_by", "signed_off_at", "created_at",
        ]


class GoLiveSignOffSerializer(serializers.Serializer):
    evidence = serializers.DictField(default=dict)


class DRDrillSerializer(serializers.ModelSerializer):
    rto_target_seconds = serializers.SerializerMethodField()
    rpo_target_seconds = serializers.SerializerMethodField()
    meets_rto = serializers.SerializerMethodField()
    meets_rpo = serializers.SerializerMethodField()

    class Meta:
        model = DRDrill
        fields = [
            "id", "drill_type", "started_at", "completed_at",
            "rto_seconds", "rpo_seconds", "passed", "notes",
            "triggered_by", "created_at",
            "rto_target_seconds", "rpo_target_seconds", "meets_rto", "meets_rpo",
        ]
        read_only_fields = ["id", "passed", "created_at"]

    def get_rto_target_seconds(self, obj):
        return DRDrill.RTO_TARGET_SECONDS

    def get_rpo_target_seconds(self, obj):
        return DRDrill.RPO_TARGET_SECONDS

    def get_meets_rto(self, obj):
        if obj.rto_seconds is None:
            return None
        return obj.rto_seconds <= DRDrill.RTO_TARGET_SECONDS

    def get_meets_rpo(self, obj):
        if obj.rpo_seconds is None:
            return None
        return obj.rpo_seconds <= DRDrill.RPO_TARGET_SECONDS


class CreateDRDrillSerializer(serializers.Serializer):
    drill_type = serializers.ChoiceField(choices=[t[0] for t in DRDrill.DRILL_TYPES])
    started_at = serializers.DateTimeField()
    completed_at = serializers.DateTimeField(required=False, allow_null=True)
    rto_seconds = serializers.IntegerField(required=False, allow_null=True, min_value=0)
    rpo_seconds = serializers.IntegerField(required=False, allow_null=True, min_value=0)
    notes = serializers.CharField(required=False, allow_blank=True, default="")
