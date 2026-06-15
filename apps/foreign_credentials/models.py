"""Foreign Credential Assessment Workflow — Phase 6 (EVS-F03).

§12(2)(l) statutory power exercised by the Director-General at the end of
this workflow. Eleven stages, two routing paths (Internal Assessor / GTEC),
HSM-backed DG signature, per-stage SLA monitoring.
"""
import uuid

from django.db import models
from django.utils import timezone


class ForeignCredentialApplication(models.Model):
    """Root entity for a foreign LLB equivalence assessment application."""

    STAGE_SUBMITTED = "submitted"
    STAGE_DOCUMENTS_PENDING = "documents_pending"
    STAGE_TRIAGED = "triaged"
    STAGE_ROUTED_INTERNAL = "routed_internal"
    STAGE_ROUTED_GTEC = "routed_gtec"
    STAGE_ASSESSOR_ASSIGNED = "assessor_assigned"
    STAGE_UNDER_REVIEW = "under_review"
    STAGE_RECOMMENDATION_MADE = "recommendation_made"
    STAGE_REGISTRAR_REVIEWED = "registrar_reviewed"
    STAGE_DG_PENDING = "dg_pending"
    STAGE_DG_SIGNED = "dg_signed"
    STAGE_CLOSED = "closed"

    STAGE_CHOICES = [
        (STAGE_SUBMITTED, "Submitted"),
        (STAGE_DOCUMENTS_PENDING, "Documents Pending"),
        (STAGE_TRIAGED, "Triaged by Registrar"),
        (STAGE_ROUTED_INTERNAL, "Routed to Internal Assessor"),
        (STAGE_ROUTED_GTEC, "Routed to GTEC"),
        (STAGE_ASSESSOR_ASSIGNED, "Assessor Assigned"),
        (STAGE_UNDER_REVIEW, "Under Review"),
        (STAGE_RECOMMENDATION_MADE, "Recommendation Made"),
        (STAGE_REGISTRAR_REVIEWED, "Registrar Reviewed"),
        (STAGE_DG_PENDING, "Awaiting DG Signature"),
        (STAGE_DG_SIGNED, "DG Signed — Decision Issued"),
        (STAGE_CLOSED, "Closed"),
    ]

    ROUTE_INTERNAL = "internal"
    ROUTE_GTEC = "gtec"
    ROUTE_UNDECIDED = ""
    ROUTE_CHOICES = [
        (ROUTE_INTERNAL, "Internal Assessor"),
        (ROUTE_GTEC, "GTEC"),
        ("", "Not yet routed"),
    ]

    OUTCOME_ACCEPTED = "accepted"
    OUTCOME_REJECTED = "rejected"
    OUTCOME_WITHDRAWN = "withdrawn"
    OUTCOME_CHOICES = [
        (OUTCOME_ACCEPTED, "Accepted — Equivalent"),
        (OUTCOME_REJECTED, "Rejected — Not Equivalent"),
        (OUTCOME_WITHDRAWN, "Withdrawn by Applicant"),
        ("", "Pending"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reference = models.CharField(max_length=30, unique=True, db_index=True,
        help_text="Human-readable reference, e.g. FCA-2026-0001.")

    # Applicant (mirrors IAM UserProfile keycloak_sub)
    applicant_sub = models.UUIDField(db_index=True,
        help_text="Keycloak subject of the applicant.")
    applicant_email = models.EmailField()
    applicant_name = models.CharField(max_length=200)

    # Foreign credential details
    foreign_institution = models.CharField(max_length=255)
    foreign_country = models.CharField(max_length=100)
    foreign_degree = models.CharField(max_length=255)
    graduation_year = models.SmallIntegerField()

    # Workflow state
    stage = models.CharField(
        max_length=25, choices=STAGE_CHOICES, default=STAGE_SUBMITTED, db_index=True
    )
    route = models.CharField(max_length=10, choices=ROUTE_CHOICES, blank=True, db_index=True)
    outcome = models.CharField(max_length=12, choices=OUTCOME_CHOICES, blank=True)

    # Actors
    triaged_by = models.UUIDField(null=True, blank=True,
        help_text="Registrar keycloak_sub.")
    triaged_at = models.DateTimeField(null=True, blank=True)
    assessor_sub = models.UUIDField(null=True, blank=True, db_index=True,
        help_text="Assigned assessor keycloak_sub (Internal or GTEC).")
    assessor_assigned_at = models.DateTimeField(null=True, blank=True)

    # SLA
    sla_due_at = models.DateTimeField(null=True, blank=True,
        help_text="Overall application SLA deadline (28 calendar days from triaged_at).")

    # DG decision
    dg_sub = models.UUIDField(null=True, blank=True,
        help_text="Director-General keycloak_sub.")
    dg_signed_at = models.DateTimeField(null=True, blank=True)
    dg_signature_ref = models.CharField(max_length=100, blank=True,
        help_text="HSM key ID of the DG signing key used.")

    # Integrity seal on the decision record
    decision_sha256 = models.CharField(max_length=64, blank=True,
        help_text="SHA-256 of the canonical decision JSON. Set at DG sign.")

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "fca_application"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["stage", "route", "created_at"]),
            models.Index(fields=["applicant_sub", "stage"]),
            models.Index(fields=["assessor_sub", "stage"]),
        ]

    def __str__(self):
        return f"{self.reference} [{self.stage}]"


class ApplicationDocument(models.Model):
    """Document submitted by the applicant or uploaded by a Registrar."""

    DOC_DEGREE_CERTIFICATE = "degree_certificate"
    DOC_TRANSCRIPT = "transcript"
    DOC_COURSE_SYLLABUS = "course_syllabus"
    DOC_IDENTITY = "identity"
    DOC_TRANSLATION = "translation"
    DOC_OTHER = "other"
    DOC_CHOICES = [
        (DOC_DEGREE_CERTIFICATE, "Degree Certificate"),
        (DOC_TRANSCRIPT, "Academic Transcript"),
        (DOC_COURSE_SYLLABUS, "Course Syllabus"),
        (DOC_IDENTITY, "Identity Document"),
        (DOC_TRANSLATION, "Certified Translation"),
        (DOC_OTHER, "Other"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    application = models.ForeignKey(
        ForeignCredentialApplication, on_delete=models.CASCADE, related_name="documents"
    )
    doc_type = models.CharField(max_length=20, choices=DOC_CHOICES)
    file_sha256 = models.CharField(max_length=64,
        help_text="SHA-256 links to DocumentVaultObject; file stored there.")
    original_filename_hash = models.CharField(max_length=64, blank=True)
    mime_type = models.CharField(max_length=100)
    uploaded_by = models.UUIDField(help_text="keycloak_sub.")
    uploaded_at = models.DateTimeField(auto_now_add=True)
    verified = models.BooleanField(default=False,
        help_text="True once a Registrar has verified the document is authentic.")

    class Meta:
        db_table = "fca_applicationdocument"
        ordering = ["doc_type", "uploaded_at"]


class WorkflowTransition(models.Model):
    """Immutable audit trail of every stage change in an application."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    application = models.ForeignKey(
        ForeignCredentialApplication, on_delete=models.CASCADE, related_name="transitions"
    )
    from_stage = models.CharField(max_length=25)
    to_stage = models.CharField(max_length=25)
    actor_sub = models.UUIDField(help_text="keycloak_sub of the actor.")
    reason = models.TextField(blank=True)
    occurred_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        db_table = "fca_workflowtransition"
        ordering = ["occurred_at"]


class AssessorAssignment(models.Model):
    """Links an assessor to an application for a specific review task."""

    TASK_ACCREDITATION = "accreditation"
    TASK_CONTENT = "content"
    TASK_CHOICES = [
        (TASK_ACCREDITATION, "Accreditation Review"),
        (TASK_CONTENT, "Content Review"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    application = models.ForeignKey(
        ForeignCredentialApplication, on_delete=models.CASCADE, related_name="assignments"
    )
    assessor_sub = models.UUIDField(db_index=True)
    task = models.CharField(max_length=15, choices=TASK_CHOICES)
    assigned_by = models.UUIDField(help_text="Registrar keycloak_sub.")
    assigned_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    sla_due_at = models.DateTimeField()

    class Meta:
        db_table = "fca_assessorassignment"
        unique_together = ("application", "assessor_sub", "task")
        ordering = ["sla_due_at"]


class EquivalenceRecommendation(models.Model):
    """Assessor's recommendation on the foreign credential equivalence."""

    RECOMMENDATION_EQUIVALENT = "equivalent"
    RECOMMENDATION_NOT_EQUIVALENT = "not_equivalent"
    RECOMMENDATION_PARTIAL = "partial_equivalent"
    RECOMMENDATION_CHOICES = [
        (RECOMMENDATION_EQUIVALENT, "Equivalent — recommend acceptance"),
        (RECOMMENDATION_NOT_EQUIVALENT, "Not equivalent — recommend rejection"),
        (RECOMMENDATION_PARTIAL, "Partially equivalent — conditional acceptance"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    application = models.ForeignKey(
        ForeignCredentialApplication, on_delete=models.CASCADE, related_name="recommendations"
    )
    assessor_sub = models.UUIDField()
    recommendation = models.CharField(max_length=20, choices=RECOMMENDATION_CHOICES)
    rationale = models.TextField(help_text="Detailed reasoning. Preserved in the tamper-evident record.")
    accreditation_ok = models.BooleanField(
        help_text="True when the institution's accreditation has been confirmed.")
    content_match_pct = models.SmallIntegerField(null=True, blank=True,
        help_text="Estimated % content overlap with GSL LLB curriculum.")
    conditions = models.TextField(blank=True,
        help_text="Any conditions attached to a partial_equivalent recommendation.")
    created_at = models.DateTimeField(auto_now_add=True)

    # Canonical JSON hash for tamper-evidence
    sha256 = models.CharField(max_length=64, blank=True)

    class Meta:
        db_table = "fca_equivalencerecommendation"
        ordering = ["-created_at"]


class DGDecision(models.Model):
    """The Director-General's final decision, signed with the HSM-backed DG key."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    application = models.OneToOneField(
        ForeignCredentialApplication, on_delete=models.PROTECT, related_name="dg_decision"
    )
    dg_sub = models.UUIDField(help_text="keycloak_sub of the Director-General.")
    outcome = models.CharField(max_length=12,
        choices=ForeignCredentialApplication.OUTCOME_CHOICES)
    decision_text = models.TextField(help_text="Official decision text — becomes part of the signed record.")
    signed_at = models.DateTimeField(default=timezone.now)
    hsm_key_id = models.CharField(max_length=100,
        help_text="HSM key ID (HsmKey.key_id) used to sign this decision.")
    signature_b64 = models.TextField(help_text="Base64-encoded RSA-PSS signature over decision_sha256.")
    decision_sha256 = models.CharField(max_length=64,
        help_text="SHA-256 of the canonical decision JSON (sorted keys, NFC, UTF-8).")
    anchor_ref = models.CharField(max_length=100, blank=True,
        help_text="System 22 (CALS) anchor reference for the integrity chain.")

    class Meta:
        db_table = "fca_dgdecision"

    def __str__(self):
        return f"DGDecision({self.application.reference}) → {self.outcome}"


class FcaSlaEvent(models.Model):
    """SLA monitoring event for a single stage of an application."""

    EVENT_ENTERED = "entered"
    EVENT_BREACHED = "breached"
    EVENT_ESCALATED = "escalated"
    EVENT_RESOLVED = "resolved"
    EVENT_CHOICES = [
        (EVENT_ENTERED, "Stage entered"),
        (EVENT_BREACHED, "SLA breached"),
        (EVENT_ESCALATED, "Escalated to Secretariat"),
        (EVENT_RESOLVED, "Stage resolved"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    application = models.ForeignKey(
        ForeignCredentialApplication, on_delete=models.CASCADE, related_name="sla_events"
    )
    stage = models.CharField(max_length=25)
    event = models.CharField(max_length=12, choices=EVENT_CHOICES)
    sla_due_at = models.DateTimeField(null=True, blank=True)
    occurred_at = models.DateTimeField(default=timezone.now, db_index=True)
    actor_sub = models.UUIDField(null=True, blank=True)

    class Meta:
        db_table = "fca_slaevent"
        ordering = ["-occurred_at"]
        indexes = [models.Index(fields=["application", "stage", "occurred_at"])]
