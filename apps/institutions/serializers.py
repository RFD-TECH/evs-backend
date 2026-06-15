"""EVS institutions serializers."""
from rest_framework import serializers

from .models import GraduationCycle, InstitutionMaster, SlaEvent


class InstitutionMasterSerializer(serializers.ModelSerializer):
    class Meta:
        model = InstitutionMaster
        fields = [
            "id", "name", "code", "accreditation_number",
            "contact_email", "is_active", "created_at", "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class InstitutionCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)
    code = serializers.CharField(max_length=20)
    accreditation_number = serializers.CharField(max_length=100, required=False, default="")
    contact_email = serializers.EmailField(required=False, default="")


class GraduationCycleSerializer(serializers.ModelSerializer):
    institution_code = serializers.CharField(source="institution.code", read_only=True)
    institution_name = serializers.CharField(source="institution.name", read_only=True)

    class Meta:
        model = GraduationCycle
        fields = [
            "id", "institution_code", "institution_name", "year", "session",
            "submission_deadline", "status",
            "submitted_at", "submitted_by",
            "sla_d20_notified", "sla_d7_notified",
            "created_at", "updated_at",
        ]
        read_only_fields = [
            "id", "institution_code", "institution_name",
            "submitted_at", "submitted_by",
            "sla_d20_notified", "sla_d7_notified",
            "created_at", "updated_at",
        ]


class GraduationCycleCreateSerializer(serializers.Serializer):
    year = serializers.IntegerField(min_value=2000, max_value=2100)
    session = serializers.CharField(max_length=50, required=False, default="")
    submission_deadline = serializers.DateField()


class SlaEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = SlaEvent
        fields = ["id", "event_type", "details", "occurred_at"]
        read_only_fields = fields
