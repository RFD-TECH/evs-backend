"""External connector platform — Phase 5 (EVS-F04 / F08).

One Connector row per integration partner (WAEC, UG, KNUST, GIMPA, GTEC …).
The platform provides lifecycle management, uptime monitoring, circuit-breaking,
rate limiting, and a manual fallback queue that all connectors share.
"""
import uuid

from django.db import models
from django.utils import timezone


class Connector(models.Model):
    """One registered external integration partner."""

    KIND_WAEC = "waec"
    KIND_FACULTY = "faculty"
    KIND_GTEC = "gtec"
    KIND_NLEMS = "nlems"
    KIND_NBES = "nbes"
    KIND_CHOICES = [
        (KIND_WAEC, "WAEC"),
        (KIND_FACULTY, "Law Faculty"),
        (KIND_GTEC, "GTEC"),
        (KIND_NLEMS, "NLEMS"),
        (KIND_NBES, "NBES"),
    ]

    LIFECYCLE_ONBOARDING = "onboarding"
    LIFECYCLE_SANDBOX = "sandbox_validated"
    LIFECYCLE_LIVE = "production_live"
    LIFECYCLE_SUSPENDED = "suspended"
    LIFECYCLE_DECOMMISSIONED = "decommissioned"
    LIFECYCLE_CHOICES = [
        (LIFECYCLE_ONBOARDING, "Onboarding"),
        (LIFECYCLE_SANDBOX, "Sandbox Validated"),
        (LIFECYCLE_LIVE, "Production Live"),
        (LIFECYCLE_SUSPENDED, "Suspended"),
        (LIFECYCLE_DECOMMISSIONED, "Decommissioned"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    kind = models.CharField(max_length=10, choices=KIND_CHOICES, db_index=True)
    sandbox_endpoint = models.URLField(blank=True)
    production_endpoint = models.URLField(blank=True)
    lifecycle_state = models.CharField(
        max_length=25, choices=LIFECYCLE_CHOICES,
        default=LIFECYCLE_ONBOARDING, db_index=True,
    )
    contact_owner = models.EmailField(blank=True)
    current_credential_id = models.UUIDField(null=True, blank=True,
        help_text="FK to ConnectorCredential.id of the active credential.")
    rate_limit_per_minute = models.PositiveIntegerField(default=60)
    latency_p95_threshold_ms = models.PositiveIntegerField(default=10000,
        help_text="Circuit-breaker opens when p95 latency exceeds this value over the rolling window.")
    sandbox_validated_at = models.DateTimeField(null=True, blank=True)
    sandbox_validation_ref = models.CharField(max_length=100, blank=True,
        help_text="AuditEvent id of the sandbox validation run.")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "connectors_connector"
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} [{self.lifecycle_state}]"

    def is_live(self) -> bool:
        return self.lifecycle_state == self.LIFECYCLE_LIVE

    @property
    def active_endpoint(self) -> str:
        if self.lifecycle_state == self.LIFECYCLE_LIVE:
            return self.production_endpoint
        return self.sandbox_endpoint


class ConnectorCredential(models.Model):
    """Auth credential attached to a connector (OAuth token, API key, mTLS cert)."""

    KIND_OAUTH = "oauth"
    KIND_API_KEY = "api_key"
    KIND_MTLS = "mtls"
    KIND_CHOICES = [
        (KIND_OAUTH, "OAuth 2.0"),
        (KIND_API_KEY, "API Key"),
        (KIND_MTLS, "mTLS"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    connector = models.ForeignKey(
        Connector, on_delete=models.CASCADE, related_name="credentials"
    )
    kind = models.CharField(max_length=10, choices=KIND_CHOICES)
    value_kid = models.CharField(max_length=100,
        help_text="HSM key ID for stored credential value. Plaintext never stored.")
    valid_from = models.DateTimeField(default=timezone.now)
    valid_until = models.DateTimeField(null=True, blank=True,
        help_text="Null means no expiry configured — prefer explicit expiry.")
    rotation_reason = models.CharField(max_length=255, blank=True)
    rotated_by = models.UUIDField(null=True, blank=True,
        help_text="keycloak_sub of the Administrator who issued this credential.")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "connectors_connectorcredential"
        ordering = ["-created_at"]

    def is_active(self) -> bool:
        now = timezone.now()
        if self.valid_from > now:
            return False
        if self.valid_until and self.valid_until < now:
            return False
        return True


class ConnectorHealth(models.Model):
    """Single synthetic probe result for a connector (F04-02)."""

    PROBE_OK = "ok"
    PROBE_DEGRADED = "degraded"
    PROBE_DOWN = "down"
    PROBE_CHOICES = [
        (PROBE_OK, "OK"),
        (PROBE_DEGRADED, "Degraded"),
        (PROBE_DOWN, "Down"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    connector = models.ForeignKey(
        Connector, on_delete=models.CASCADE, related_name="health_checks"
    )
    ts = models.DateTimeField(default=timezone.now, db_index=True)
    probe_result = models.CharField(max_length=10, choices=PROBE_CHOICES)
    latency_ms = models.PositiveIntegerField(null=True, blank=True)
    error_code = models.CharField(max_length=50, blank=True)

    class Meta:
        db_table = "connectors_connectorhealth"
        ordering = ["-ts"]
        indexes = [
            models.Index(fields=["connector", "ts"]),
            models.Index(fields=["connector", "probe_result", "ts"]),
        ]


class BreakerState(models.Model):
    """Current and historical circuit-breaker state per connector (F04-02)."""

    STATE_CLOSED = "closed"
    STATE_HALF_OPEN = "half_open"
    STATE_OPEN = "open"
    STATE_CHOICES = [
        (STATE_CLOSED, "Closed — healthy"),
        (STATE_HALF_OPEN, "Half-open — probing"),
        (STATE_OPEN, "Open — failing fast"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    connector = models.ForeignKey(
        Connector, on_delete=models.CASCADE, related_name="breaker_states"
    )
    state = models.CharField(max_length=10, choices=STATE_CHOICES, db_index=True)
    since = models.DateTimeField(default=timezone.now)
    reason = models.CharField(max_length=255, blank=True,
        help_text="Why the breaker transitioned to this state.")
    error_rate_pct = models.FloatField(null=True, blank=True,
        help_text="Error rate % over the rolling window that triggered the open transition.")
    consecutive_probe_successes = models.PositiveSmallIntegerField(default=0,
        help_text="Successful half-open probes before auto-close.")

    class Meta:
        db_table = "connectors_breakerstate"
        ordering = ["-since"]
        indexes = [models.Index(fields=["connector", "state", "since"])]

    def __str__(self):
        return f"{self.connector.name} breaker={self.state}"


class ManualQueueItem(models.Model):
    """A verification that could not be automated and awaits Registrar resolution (F04-04)."""

    STATUS_PENDING = "pending"
    STATUS_CLAIMED = "claimed"
    STATUS_RESOLVED = "resolved"
    STATUS_ESCALATED = "escalated"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_CLAIMED, "Claimed by Registrar"),
        (STATUS_RESOLVED, "Resolved"),
        (STATUS_ESCALATED, "Escalated to Secretariat"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    connector = models.ForeignKey(
        Connector, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="queue_items",
    )
    original_payload = models.JSONField(
        help_text="Sanitised request payload — PII stripped per retention rules.")
    consumer_id = models.CharField(max_length=50, blank=True,
        help_text="System identifier of the originating consumer (e.g. NLEMS, NBES).")
    status = models.CharField(max_length=12, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True)
    queued_at = models.DateTimeField(default=timezone.now, db_index=True)
    sla_due_at = models.DateTimeField(db_index=True,
        help_text="SLA deadline — items past this date escalate automatically.")
    claimed_by = models.UUIDField(null=True, blank=True,
        help_text="keycloak_sub of the Registrar who claimed this item.")
    claimed_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_status = models.CharField(max_length=20, blank=True,
        help_text="e.g. verified, not_found, mismatch — same vocabulary as VerificationSession.result.")
    justification = models.TextField(blank=True)
    result_id = models.UUIDField(null=True, blank=True,
        help_text="VerificationSession.id minted when resolved.")
    attempt_count = models.PositiveSmallIntegerField(default=1)

    class Meta:
        db_table = "connectors_manualqueueitem"
        ordering = ["sla_due_at"]
        indexes = [
            models.Index(fields=["status", "sla_due_at"]),
            models.Index(fields=["connector", "status"]),
        ]

    def __str__(self):
        return f"Queue[{self.id}] {self.status} due={self.sla_due_at.date()}"


class WaecRequest(models.Model):
    """WAEC-specific verification record (F08 — one row per upstream call or queue entry)."""

    RESPONSE_VERIFIED = "verified"
    RESPONSE_NOT_FOUND = "not_found"
    RESPONSE_MISMATCH = "mismatch"
    RESPONSE_API_ERROR = "api_error"
    RESPONSE_QUEUED = "queued"
    RESPONSE_CHOICES = [
        (RESPONSE_VERIFIED, "Verified – Matches Official Record"),
        (RESPONSE_NOT_FOUND, "Not Found"),
        (RESPONSE_MISMATCH, "Mismatch in Details"),
        (RESPONSE_API_ERROR, "API Error"),
        (RESPONSE_QUEUED, "Queued for Manual Verification"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    index_number = models.CharField(max_length=30)
    year_of_completion = models.SmallIntegerField()
    examination_series = models.CharField(max_length=10,
        help_text="Private or Regular.")
    dob_masked = models.CharField(max_length=20,
        help_text="Date of birth stored as MM/****  (day and year masked for PII compliance).")
    request_payload_hash = models.CharField(max_length=64,
        help_text="SHA-256 of the outbound WAEC request for evidentiary linkage.")
    response_status = models.CharField(max_length=10, choices=RESPONSE_CHOICES, db_index=True)
    sanitised_response = models.JSONField(null=True, blank=True,
        help_text="Subset of the WAEC response permitted by the sanitisation rules.")
    latency_ms = models.PositiveIntegerField(null=True, blank=True)
    queued_flag = models.BooleanField(default=False,
        help_text="True when circuit-breaker was open and the request was queued.")
    result_id = models.UUIDField(null=True, blank=True,
        help_text="VerificationSession.id minted for this verification.")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "connectors_waecrequests"
        ordering = ["-created_at"]
