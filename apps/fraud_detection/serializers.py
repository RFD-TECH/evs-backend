"""Serializers for fraud detection models (EVS-F05)."""
from __future__ import annotations

from rest_framework import serializers

from . import rules_engine as _engine
from .models import FlagAction, FraudFlag, RuleDefinition, RuleRun, WatchlistEntry


class RuleDefinitionSerializer(serializers.ModelSerializer):
    class Meta:
        model = RuleDefinition
        fields = [
            "id", "name", "description", "severity_default", "predicate_json",
            "evidence_template", "version", "enabled", "created_by",
            "approved_by", "second_approver", "effective_from", "deprecated_at",
            "created_at", "updated_at",
        ]
        read_only_fields = ["id", "version", "created_at", "updated_at"]

    def validate_predicate_json(self, value):
        errors = _engine.validate_predicate(value)
        if errors:
            raise serializers.ValidationError(errors)
        return value


class RuleDefinitionActivateSerializer(serializers.Serializer):
    approver_id = serializers.UUIDField()

    def validate(self, attrs):
        rule: RuleDefinition = self.context["rule"]
        approver_id = attrs["approver_id"]
        request_user_id = self.context["request_user_id"]

        if rule.enabled:
            raise serializers.ValidationError("Rule is already enabled.")

        if not rule.approved_by:
            raise serializers.ValidationError(
                "First approval is missing. POST to /approve first."
            )
        if str(approver_id) == str(rule.created_by):
            raise serializers.ValidationError(
                "Second approver may not be the rule author."
            )
        if str(approver_id) == str(rule.approved_by):
            raise serializers.ValidationError(
                "Second approver must differ from the first approver."
            )
        return attrs


class RuleDryRunSerializer(serializers.Serializer):
    predicate_json = serializers.JSONField()
    credential_ids = serializers.ListField(
        child=serializers.UUIDField(), max_length=500, required=False
    )

    def validate_predicate_json(self, value):
        errors = _engine.validate_predicate(value)
        if errors:
            raise serializers.ValidationError(errors)
        return value


class RuleRunSerializer(serializers.ModelSerializer):
    class Meta:
        model = RuleRun
        fields = [
            "id", "trigger", "triggered_by", "batch_id",
            "run_started_at", "run_finished_at",
            "records_scanned", "rules_evaluated", "flags_created",
            "status", "error_message",
        ]
        read_only_fields = fields


class FlagActionSerializer(serializers.ModelSerializer):
    class Meta:
        model = FlagAction
        fields = ["id", "action", "actor_user_id", "occurred_at", "payload", "audit_chain_ref"]
        read_only_fields = fields


class FraudFlagSerializer(serializers.ModelSerializer):
    actions = FlagActionSerializer(many=True, read_only=True)

    class Meta:
        model = FraudFlag
        fields = [
            "id", "flag_type", "credential_ids", "applicant_ids",
            "rule", "run", "severity", "status",
            "evidence_payload", "evidence_bundle_uri", "fuzzy_similarity_score",
            "resolution_justification", "resolver_id", "resolved_at",
            "audit_hash", "escalated_at", "created_at", "updated_at",
            "actions",
        ]
        read_only_fields = [
            "id", "flag_type", "credential_ids", "applicant_ids",
            "rule", "run", "severity", "evidence_payload",
            "evidence_bundle_uri", "fuzzy_similarity_score",
            "audit_hash", "escalated_at", "created_at", "updated_at",
            "actions",
        ]


class FlagResolutionSerializer(serializers.Serializer):
    new_status = serializers.ChoiceField(choices=[
        FraudFlag.STATUS_CONFIRMED_FRAUD,
        FraudFlag.STATUS_FALSE_POSITIVE,
        FraudFlag.STATUS_UNDER_INVESTIGATION,
    ])
    justification = serializers.CharField(min_length=1)

    def validate_justification(self, value):
        words = len(value.split())
        if words < 30:
            raise serializers.ValidationError(
                f"Justification must be ≥30 words (got {words})."
            )
        return value

    def validate(self, attrs):
        flag: FraudFlag = self.context["flag"]
        new_status = attrs["new_status"]
        if flag.status in [FraudFlag.STATUS_CONFIRMED_FRAUD, FraudFlag.STATUS_FALSE_POSITIVE]:
            raise serializers.ValidationError(
                f"Flag is already in terminal status '{flag.status}'."
            )
        if (new_status == FraudFlag.STATUS_UNDER_INVESTIGATION
                and flag.status == FraudFlag.STATUS_UNDER_INVESTIGATION):
            raise serializers.ValidationError("Flag is already under investigation.")
        return attrs


class FlagAddendumSerializer(serializers.Serializer):
    note = serializers.CharField(min_length=1, max_length=4000)
    additional_evidence = serializers.JSONField(required=False, default=dict)


class WatchlistEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = WatchlistEntry
        fields = [
            "id", "applicant_id", "reason_flag", "added_at", "added_by",
            "status", "cleared_at", "cleared_reason",
        ]
        read_only_fields = ["id", "reason_flag", "added_at", "added_by"]


class WatchlistClearSerializer(serializers.Serializer):
    cleared_reason = serializers.CharField(min_length=1, max_length=2000)


class FraudRunRequestSerializer(serializers.Serializer):
    trigger = serializers.ChoiceField(choices=[
        RuleRun.TRIGGER_ON_DEMAND, RuleRun.TRIGGER_POST_INGEST,
    ], default=RuleRun.TRIGGER_ON_DEMAND)
    batch_id = serializers.UUIDField(required=False, allow_null=True)
    fuzzy_threshold = serializers.FloatField(
        required=False, min_value=0.5, max_value=0.99, default=0.85
    )
