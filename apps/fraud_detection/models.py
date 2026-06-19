"""Fraud detection models — Phase 7 (EVS-F05).

Flags are not verdicts. An automatically generated flag is a structured invitation
for a Registrar to look. Every flag is resolvable as Confirmed Fraud, False Positive,
or Under Investigation — and every resolution requires a ≥30-word justification.
"""
import uuid

from django.db import models
from django.utils import timezone


class RuleDefinition(models.Model):
    """Configurable fraud detection rule (EVS-F05-04).

    Rules are versioned and require dual-control Administrator activation.
    Predicates are stored as JSON and evaluated by the rules engine.
    Activation requires two distinct Administrator IDs (second may not be the author).
    """

    SEVERITY_LOW = "low"
    SEVERITY_MEDIUM = "medium"
    SEVERITY_HIGH = "high"
    SEVERITY_CHOICES = [
        (SEVERITY_LOW, "Low"),
        (SEVERITY_MEDIUM, "Medium"),
        (SEVERITY_HIGH, "High"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    severity_default = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default=SEVERITY_MEDIUM)
    predicate_json = models.JSONField(
        help_text="JSON predicate tree evaluated against each credential payload.")
    evidence_template = models.TextField(blank=True,
        help_text="Narrative template for the evidence package.")
    version = models.PositiveIntegerField(default=1)
    enabled = models.BooleanField(default=False, db_index=True)
    created_by = models.UUIDField(null=True, blank=True,
        help_text="keycloak_sub of the authoring Administrator.")
    approved_by = models.UUIDField(null=True, blank=True,
        help_text="First approver — must differ from created_by.")
    second_approver = models.UUIDField(null=True, blank=True,
        help_text="Second approver — activation requires both distinct approvers.")
    effective_from = models.DateTimeField(null=True, blank=True, db_index=True,
        help_text="Rule activates at the next scheduled sweep at or after this time.")
    deprecated_at = models.DateTimeField(null=True, blank=True,
        help_text="Deprecated rules are retained for historical re-evaluation.")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "fraud_ruledefinition"
        ordering = ["name", "-version"]

    def __str__(self):
        state = "enabled" if self.enabled else "disabled"
        return f"{self.name} v{self.version} [{state}]"


class RuleRun(models.Model):
    """Record of a single detection run execution (EVS-F05-01)."""

    TRIGGER_POST_INGEST = "post_ingest"
    TRIGGER_NIGHTLY = "nightly"
    TRIGGER_ON_DEMAND = "on_demand"
    TRIGGER_CHOICES = [
        (TRIGGER_POST_INGEST, "Post-Ingest"),
        (TRIGGER_NIGHTLY, "Nightly Full Sweep"),
        (TRIGGER_ON_DEMAND, "On-Demand"),
    ]

    STATUS_RUNNING = "running"
    STATUS_COMPLETED = "completed"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_RUNNING, "Running"),
        (STATUS_COMPLETED, "Completed"),
        (STATUS_FAILED, "Failed"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    trigger = models.CharField(max_length=15, choices=TRIGGER_CHOICES, db_index=True)
    triggered_by = models.UUIDField(null=True, blank=True,
        help_text="Actor keycloak_sub for on-demand runs; null for scheduled.")
    batch_id = models.UUIDField(null=True, blank=True, db_index=True,
        help_text="BatchIngest.id for post-ingest trigger.")
    run_started_at = models.DateTimeField(default=timezone.now, db_index=True)
    run_finished_at = models.DateTimeField(null=True, blank=True)
    records_scanned = models.PositiveIntegerField(default=0)
    rules_evaluated = models.PositiveIntegerField(default=0)
    flags_created = models.PositiveIntegerField(default=0)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default=STATUS_RUNNING, db_index=True)
    error_message = models.TextField(blank=True)

    class Meta:
        db_table = "fraud_rulerun"
        ordering = ["-run_started_at"]

    def __str__(self):
        return f"Run({self.trigger}) @ {self.run_started_at.date()} → {self.flags_created} flags"


class FraudFlag(models.Model):
    """A fraud signal raised by the detection engine (EVS-F05-05).

    Evidence packages are stored immutably — once assembled, only addenda can add context.
    Flags are never deletable; corrections require an addendum with a fresh justification.
    """

    SEVERITY_LOW = "low"
    SEVERITY_MEDIUM = "medium"
    SEVERITY_HIGH = "high"
    SEVERITY_CHOICES = [
        (SEVERITY_LOW, "Low"),
        (SEVERITY_MEDIUM, "Medium"),
        (SEVERITY_HIGH, "High"),
    ]

    STATUS_NEW = "new"
    STATUS_UNDER_INVESTIGATION = "under_investigation"
    STATUS_CONFIRMED_FRAUD = "confirmed_fraud"
    STATUS_FALSE_POSITIVE = "false_positive"
    STATUS_CHOICES = [
        (STATUS_NEW, "New"),
        (STATUS_UNDER_INVESTIGATION, "Under Investigation"),
        (STATUS_CONFIRMED_FRAUD, "Confirmed Fraud"),
        (STATUS_FALSE_POSITIVE, "False Positive"),
    ]

    FLAG_DUPLICATE_CREDENTIAL = "duplicate_credential"
    FLAG_DUPLICATE_INDEX = "duplicate_index"
    FLAG_FUZZY_IDENTITY = "fuzzy_identity"
    FLAG_RULE_MATCH = "rule_match"
    FLAG_TYPE_CHOICES = [
        (FLAG_DUPLICATE_CREDENTIAL, "Duplicate Credential Usage"),
        (FLAG_DUPLICATE_INDEX, "Duplicate Graduate Index (Exact)"),
        (FLAG_FUZZY_IDENTITY, "Fuzzy Identity Match"),
        (FLAG_RULE_MATCH, "Metadata Anomaly Rule"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    flag_type = models.CharField(max_length=25, choices=FLAG_TYPE_CHOICES, db_index=True)
    credential_ids = models.JSONField(default=list,
        help_text="List of Credential UUID strings involved in this flag.")
    applicant_ids = models.JSONField(default=list,
        help_text="List of applicant keycloak_sub strings.")
    rule = models.ForeignKey(
        RuleDefinition, on_delete=models.PROTECT, null=True, blank=True,
        related_name="flags",
        help_text="Set when flag_type is rule_match.",
    )
    run = models.ForeignKey(
        RuleRun, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="flags",
    )
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, db_index=True)
    status = models.CharField(max_length=25, choices=STATUS_CHOICES, default=STATUS_NEW, db_index=True)
    evidence_payload = models.JSONField(default=dict,
        help_text="Linked records, diff highlights, rule context.")
    evidence_bundle_uri = models.CharField(max_length=500, blank=True,
        help_text="URI of the signed, downloadable evidence bundle.")
    fuzzy_similarity_score = models.FloatField(null=True, blank=True,
        help_text="Levenshtein similarity ratio for fuzzy_identity flags.")
    resolution_justification = models.TextField(blank=True,
        help_text="Mandatory ≥30-word justification. Normalised before word-count check.")
    resolver_id = models.UUIDField(null=True, blank=True,
        help_text="keycloak_sub of the Registrar who resolved this flag.")
    resolved_at = models.DateTimeField(null=True, blank=True)
    audit_hash = models.CharField(max_length=64, blank=True,
        help_text="SHA-256 of the immutable audit chain entry anchored to System 22.")
    escalated_at = models.DateTimeField(null=True, blank=True,
        help_text="When the auto-escalation notification was sent.")
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "fraud_fraudflag"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["severity", "status", "created_at"]),
            models.Index(fields=["status", "escalated_at"]),
            models.Index(fields=["flag_type", "status"]),
        ]

    def __str__(self):
        return f"Flag[{self.severity.upper()}] {self.flag_type} [{self.status}]"


class WatchlistEntry(models.Model):
    """Applicants placed on the fraud watchlist after Confirmed Fraud (EVS-F05-07).

    Consulted by NLEMS, NBES, and Phase 6 FCA triage. 60-second freshness target
    with push-based cache invalidation.
    """

    STATUS_ACTIVE = "active"
    STATUS_CLEARED = "cleared"
    STATUS_CHOICES = [
        (STATUS_ACTIVE, "Active"),
        (STATUS_CLEARED, "Cleared"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    applicant_id = models.UUIDField(db_index=True,
        help_text="Keycloak subject UUID of the flagged applicant.")
    reason_flag = models.ForeignKey(
        FraudFlag, on_delete=models.PROTECT, related_name="watchlist_entries",
    )
    added_at = models.DateTimeField(default=timezone.now, db_index=True)
    added_by = models.UUIDField(help_text="keycloak_sub of the actor.")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_ACTIVE, db_index=True)
    cleared_at = models.DateTimeField(null=True, blank=True)
    cleared_reason = models.TextField(blank=True)

    class Meta:
        db_table = "fraud_watchlistentry"
        ordering = ["-added_at"]
        indexes = [models.Index(fields=["applicant_id", "status"])]

    def __str__(self):
        return f"Watchlist({self.applicant_id})[{self.status}]"


class FlagAction(models.Model):
    """Immutable audit trail of every action taken on a fraud flag (EVS-F05-08).

    Retention 10 years per N02. Every action anchors to System 22 within 1 second.
    """

    ACTION_CREATED = "created"
    ACTION_VIEWED = "viewed"
    ACTION_ESCALATED = "escalated"
    ACTION_STATUS_CHANGE = "status_change"
    ACTION_RESOLVED = "resolved"
    ACTION_ADDENDUM = "addendum"
    ACTION_CHOICES = [
        (ACTION_CREATED, "Created"),
        (ACTION_VIEWED, "Viewed"),
        (ACTION_ESCALATED, "Escalated"),
        (ACTION_STATUS_CHANGE, "Status Change"),
        (ACTION_RESOLVED, "Resolved"),
        (ACTION_ADDENDUM, "Addendum Added"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    flag = models.ForeignKey(
        FraudFlag, on_delete=models.PROTECT, related_name="actions",
    )
    actor_user_id = models.UUIDField(null=True, blank=True,
        help_text="keycloak_sub of the acting user; null for system actions.")
    action = models.CharField(max_length=20, choices=ACTION_CHOICES, db_index=True)
    occurred_at = models.DateTimeField(default=timezone.now, db_index=True)
    payload = models.JSONField(default=dict,
        help_text="Context: old/new status, justification, escalation target, etc.")
    audit_chain_ref = models.CharField(max_length=100, blank=True,
        help_text="AuditEvent.id anchored to System 22.")

    class Meta:
        db_table = "fraud_flagaction"
        ordering = ["occurred_at"]

    def __str__(self):
        return f"FlagAction({self.flag_id})[{self.action}] @ {self.occurred_at}"
