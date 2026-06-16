"""Institution master, graduation cycles, and SLA events."""
import uuid

from django.db import models
from django.utils import timezone


class InstitutionMaster(models.Model):
    """Accredited institution authorised to submit graduation credential data."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)
    code = models.CharField(max_length=20, unique=True, db_index=True,
        help_text="Short code, e.g. GSL, KSL, GIMPA.")
    country_code = models.CharField(max_length=3, default="GH", db_index=True,
        help_text="ISO 3166-1 alpha-3 country code.")
    accreditation_number = models.CharField(max_length=100, blank=True)
    contact_email = models.EmailField(blank=True)
    programmes = models.JSONField(default=list,
        help_text="List of programme descriptors offered by the institution.")
    contact_officers = models.JSONField(default=list,
        help_text="List of {name, email, phone} for institution liaison officers.")
    api_keys = models.JSONField(default=dict,
        help_text="Hashed API key metadata for M2M access (never store plain keys).")
    is_active = models.BooleanField(default=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "institutions_institutionmaster"
        ordering = ["name"]

    def __str__(self):
        return f"{self.code} — {self.name}"


class GraduationCycle(models.Model):
    """One graduation submission window for an institution."""

    STATUS_OPEN = "open"
    STATUS_SUBMITTED = "submitted"
    STATUS_CLOSED = "closed"
    STATUS_OVERDUE = "overdue"
    STATUS_CHOICES = [
        (STATUS_OPEN, "Open"),
        (STATUS_SUBMITTED, "Submitted"),
        (STATUS_CLOSED, "Closed"),
        (STATUS_OVERDUE, "Overdue"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    institution = models.ForeignKey(
        InstitutionMaster, on_delete=models.CASCADE, related_name="cycles",
    )
    year = models.PositiveIntegerField()
    session = models.CharField(max_length=50, blank=True,
        help_text="Human-readable label, e.g. 'July 2024'.")
    submission_deadline = models.DateField(
        help_text="Date by which the institution must submit all credential data.",
    )
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default=STATUS_OPEN, db_index=True)
    submitted_at = models.DateTimeField(null=True, blank=True)
    submitted_by = models.UUIDField(null=True, blank=True,
        help_text="UserProfile.id of the institution officer who finalised submission.")
    sla_d20_notified = models.BooleanField(default=False,
        help_text="True once the D-20 (20 days remaining) reminder has been sent.")
    sla_d28_notified = models.BooleanField(default=False,
        help_text="True once the D-28 (28 days remaining) statutory reminder has been sent.")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "institutions_graduationcycle"
        unique_together = [("institution", "year", "session")]
        ordering = ["-year", "institution__code"]
        indexes = [
            models.Index(fields=["status", "submission_deadline"]),
        ]

    def __str__(self):
        return f"{self.institution.code} {self.year} {self.session} [{self.status}]"


class SlaEvent(models.Model):
    """SLA monitoring event logged for a graduation cycle."""

    EVENT_D20_REMINDER = "d20_reminder"
    EVENT_D28_REMINDER = "d28_reminder"
    EVENT_OVERDUE_ESCALATION = "overdue_escalation"
    EVENT_SUBMISSION_RECEIVED = "submission_received"
    EVENT_CHOICES = [
        (EVENT_D20_REMINDER, "D-20 Reminder Sent"),
        (EVENT_D28_REMINDER, "D-28 Statutory Reminder Sent"),
        (EVENT_OVERDUE_ESCALATION, "Overdue Escalation"),
        (EVENT_SUBMISSION_RECEIVED, "Submission Received"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    cycle = models.ForeignKey(GraduationCycle, on_delete=models.CASCADE, related_name="sla_events")
    event_type = models.CharField(max_length=30, choices=EVENT_CHOICES, db_index=True)
    details = models.JSONField(default=dict)
    occurred_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        db_table = "institutions_slaevent"
        ordering = ["-occurred_at"]

    def __str__(self):
        return f"{self.cycle} → {self.event_type} @ {self.occurred_at.date()}"
