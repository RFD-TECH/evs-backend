"""Foreign Credential Assessment serializers — Phase 6."""
from rest_framework import serializers

from .models import (
    ApplicationDocument, DGDecision, EquivalenceRecommendation,
    FcaSlaEvent, ForeignCredentialApplication, WorkflowTransition,
)


class ForeignCredentialApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = ForeignCredentialApplication
        fields = [
            "id", "reference", "applicant_sub", "applicant_email", "applicant_name",
            "foreign_institution", "foreign_country", "foreign_degree", "graduation_year",
            "stage", "route", "outcome", "triaged_by", "triaged_at",
            "assessor_sub", "assessor_assigned_at", "sla_due_at",
            "dg_sub", "dg_signed_at", "created_at", "updated_at",
        ]
        read_only_fields = fields


class ForeignCredentialSubmitSerializer(serializers.Serializer):
    applicant_name = serializers.CharField(max_length=200)
    applicant_email = serializers.EmailField()
    foreign_institution = serializers.CharField(max_length=255)
    foreign_country = serializers.CharField(max_length=100)
    foreign_degree = serializers.CharField(max_length=255)
    graduation_year = serializers.IntegerField(min_value=1950, max_value=2100)


class TriageSerializer(serializers.Serializer):
    route = serializers.ChoiceField(choices=["internal", "gtec"])
    notes = serializers.CharField(max_length=500, allow_blank=True, default="")


class AssignAssessorSerializer(serializers.Serializer):
    assessor_sub = serializers.UUIDField()
    task = serializers.ChoiceField(choices=["accreditation", "content"])


class RecommendationSerializer(serializers.Serializer):
    recommendation = serializers.ChoiceField(
        choices=["equivalent", "not_equivalent", "partial_equivalent"]
    )
    rationale = serializers.CharField(min_length=50)
    accreditation_ok = serializers.BooleanField()
    content_match_pct = serializers.IntegerField(min_value=0, max_value=100, required=False, allow_null=True)
    conditions = serializers.CharField(allow_blank=True, default="")


class RegistrarReviewSerializer(serializers.Serializer):
    notes = serializers.CharField(max_length=500, allow_blank=True, default="")


class DGSignSerializer(serializers.Serializer):
    outcome = serializers.ChoiceField(choices=["accepted", "rejected"])
    decision_text = serializers.CharField(min_length=20)
    hsm_key_id = serializers.CharField(max_length=100)


class DGDecisionSerializer(serializers.ModelSerializer):
    class Meta:
        model = DGDecision
        fields = [
            "id", "dg_sub", "outcome", "decision_text",
            "signed_at", "decision_sha256", "anchor_ref",
        ]
        read_only_fields = fields


class ApplicationDocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = ApplicationDocument
        fields = [
            "id", "doc_type", "file_sha256", "mime_type",
            "uploaded_by", "uploaded_at", "verified",
        ]
        read_only_fields = fields


class WorkflowTransitionSerializer(serializers.ModelSerializer):
    class Meta:
        model = WorkflowTransition
        fields = ["id", "from_stage", "to_stage", "actor_sub", "reason", "occurred_at"]
        read_only_fields = fields


class EquivalenceRecommendationSerializer(serializers.ModelSerializer):
    class Meta:
        model = EquivalenceRecommendation
        fields = [
            "id", "assessor_sub", "recommendation", "rationale",
            "accreditation_ok", "content_match_pct", "conditions", "sha256", "created_at",
        ]
        read_only_fields = fields
