"""Append-only audit trail with SHA-256 hash chain (EVS-N01, EVS-N02)."""
import hashlib
import json
import logging
import uuid

from django.db import models, transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

_STATE_CHANGE_ACTIONS = frozenset({
    "USER_UPDATED", "USER_DEACTIVATED", "ROLE_ASSIGNED", "ROLE_REVOKED",
    "CREDENTIAL_REVOKED", "CREDENTIAL_QUARANTINED",
    "BATCH_INGEST_COMPLETED", "INSTITUTION_UPDATED",
    "FRAUD_FLAG_RESOLVED", "FOREIGN_DECISION_RECORDED",
    "VERIFICATION_RESULT_PUBLISHED",
})


class AuditEvent(models.Model):
    """
    Append-only audit event store.
    DB trigger (via migration RunSQL) prevents UPDATE/DELETE.
    10-year statutory retention (EVS-N02).
    """

    id = models.BigAutoField(primary_key=True)
    event_id = models.UUIDField(db_index=True, default=uuid.uuid4)
    actor_id = models.UUIDField(null=True, blank=True)
    action = models.CharField(max_length=100)
    entity_type = models.CharField(max_length=100, blank=True, default="")
    entity_id = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    old_state = models.JSONField(null=True, blank=True)
    new_state = models.JSONField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    request_id = models.UUIDField(null=True, blank=True)
    source_system = models.CharField(max_length=20, default="evs")
    chain_hash = models.CharField(max_length=64)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "audit_auditevent"
        ordering = ["id"]
        verbose_name = "Audit Event"

    def __str__(self):
        return f"{self.action} on {self.entity_type}:{self.entity_id}"

    @classmethod
    def record(cls, *, action: str, **kwargs) -> "AuditEvent":
        if action in _STATE_CHANGE_ACTIONS and kwargs.get("old_state") is None:
            raise ValueError(
                f"audit.missing_old_state action={action} — supply old_state for state-change actions"
            )
        with transaction.atomic():
            return cls._record_atomic(action=action, **kwargs)

    @classmethod
    def _record_atomic(cls, *, action: str, **kwargs) -> "AuditEvent":
        last = cls.objects.select_for_update().order_by("-id").values("chain_hash").first()
        previous_hash = last["chain_hash"] if last else "0" * 64

        event_id = kwargs.pop("event_id", uuid.uuid4())
        created_at = kwargs.pop("created_at", timezone.now())

        payload = json.dumps(
            {
                "event_id": str(event_id),
                "actor_id": str(kwargs.get("actor_id", "")),
                "action": action,
                "entity_type": kwargs.get("entity_type", ""),
                "entity_id": str(kwargs.get("entity_id", "")),
                "old_state": kwargs.get("old_state") or {},
                "new_state": kwargs.get("new_state") or {},
                "created_at": created_at.isoformat(),
            },
            sort_keys=True,
        )

        chain_hash = hashlib.sha256(f"{previous_hash}{payload}".encode()).hexdigest()

        event = cls.objects.create(
            event_id=event_id,
            action=action,
            chain_hash=chain_hash,
            created_at=created_at,
            **kwargs,
        )

        from shared.events import publish
        publish("AuditEventRecorded", {"event_id": str(event.event_id), "chain_hash": chain_hash}, topic="evs.audit")

        # Relay to CALS (System 22) via System 17 — best-effort
        try:
            from shared.integrations.system17 import get_system17_client
            get_system17_client().relay_audit_event(
                action=action,
                resource_type=kwargs.get("entity_type") or "resource",
                resource_id=str(kwargs.get("entity_id") or ""),
                user_id=str(kwargs.get("actor_id") or ""),
                principal=str(kwargs.get("actor_id") or "system"),
                previous_hash=previous_hash,
                current_hash=chain_hash,
                trace_id=str(kwargs.get("request_id") or event_id),
            )
        except Exception as exc:
            logger.warning("system17.relay.error action=%s err=%s", action, exc)

        return event


class OutboxEvent(models.Model):
    """Transactional outbox — polled every 5 seconds by Celery."""

    id = models.BigAutoField(primary_key=True)
    correlation_id = models.UUIDField(unique=True, default=uuid.uuid4)
    request_id = models.UUIDField(null=True, blank=True, db_index=True)
    traceparent = models.CharField(max_length=255, null=True, blank=True)
    tracestate = models.TextField(null=True, blank=True)
    topic = models.CharField(max_length=100)
    event_name = models.CharField(max_length=100)
    payload = models.JSONField()
    published = models.BooleanField(default=False, db_index=True)
    published_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        db_table = "audit_outboxevent"
        indexes = [models.Index(fields=["published", "created_at"])]

    def __str__(self):
        return f"{self.event_name} → {self.topic} ({'sent' if self.published else 'pending'})"


class SecurityEvent(models.Model):
    CATEGORY_CHOICES = [
        ("auth_token_invalid", "auth_token_invalid"),
        ("auth_token_expired", "auth_token_expired"),
        ("auth_audience_mismatch", "auth_audience_mismatch"),
        ("authz_denied", "authz_denied"),
        ("step_up_denied", "step_up_denied"),
        ("throttle_applied", "throttle_applied"),
        ("ip_blocked", "ip_blocked"),
        ("anomaly_detected", "anomaly_detected"),
        ("role_conflict_in_jwt", "role_conflict_in_jwt"),
        ("fraud_flag_raised", "fraud_flag_raised"),
    ]
    SEVERITY_CHOICES = [("info", "info"), ("warning", "warning"), ("high", "high")]

    id = models.BigAutoField(primary_key=True)
    event_id = models.UUIDField(unique=True, default=uuid.uuid4)
    category = models.CharField(max_length=40, choices=CATEGORY_CHOICES, db_index=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default="warning")
    indicators = models.JSONField(default=dict)
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    actor_id = models.UUIDField(null=True, blank=True, db_index=True)
    request_id = models.UUIDField(null=True, blank=True)
    occurred_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        db_table = "audit_securityevent"
        ordering = ["-occurred_at"]
        indexes = [
            models.Index(fields=["category", "occurred_at"]),
            models.Index(fields=["ip_address", "occurred_at"]),
        ]

    def __str__(self):
        return f"{self.category}@{self.ip_address or '-'} {self.occurred_at.isoformat()}"


class DailyHashAnchor(models.Model):
    """Daily chain root anchored to System 22 at 02:00 UTC."""

    date = models.DateField(unique=True, db_index=True)
    head_event_id = models.UUIDField(null=True, blank=True)
    head_hash = models.CharField(max_length=64)
    event_count = models.PositiveIntegerField(default=0)
    exported_to_s22_at = models.DateTimeField(null=True, blank=True)
    anchor_ref = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "audit_dailyhashanchor"
        ordering = ["-date"]
        verbose_name = "Daily Hash Anchor"

    def __str__(self):
        return f"{self.date.isoformat()} → {self.head_hash[:12]}…"


# ── Phase 9 Models ────────────────────────────────────────────────────────────


class DailyCommitment(models.Model):
    """Daily cryptographic commitment anchoring the audit chain and integrity manifest.

    Chains commitments via ``prev_commitment_hash`` so any gap is detectable.
    The ``commitment_hash`` is SHA-256 of ``prev_commitment_hash + integrity_merkle_root + head_hash``.
    Signed by the HSM integrity key before submission to System 22 (CALS).
    """

    STATUS_PENDING = "pending"
    STATUS_SUBMITTED = "submitted"
    STATUS_CONFIRMED = "confirmed"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending — not yet submitted to System 22"),
        (STATUS_SUBMITTED, "Submitted — awaiting System 22 confirmation"),
        (STATUS_CONFIRMED, "Confirmed — System 22 receipt received"),
        (STATUS_FAILED, "Failed — submission error; requires manual retry"),
    ]

    date = models.DateField(unique=True, db_index=True)
    anchor = models.OneToOneField(
        DailyHashAnchor, on_delete=models.PROTECT, related_name="commitment",
        null=True, blank=True,
        help_text="The DailyHashAnchor that seeds the head_hash for this commitment.",
    )
    integrity_merkle_root = models.CharField(
        max_length=64, blank=True, default="",
        help_text="SHA-256 Merkle root of all credential {id}:{sha256} pairs from the nightly sweep.",
    )
    prev_commitment_hash = models.CharField(
        max_length=64,
        help_text="commitment_hash of the previous day's DailyCommitment (or 64× '0' for genesis).",
    )
    commitment_hash = models.CharField(
        max_length=64, db_index=True,
        help_text="SHA-256(prev_commitment_hash + integrity_merkle_root + head_hash).",
    )
    hsm_signature = models.TextField(
        blank=True, default="",
        help_text="Base64-encoded HSM signature over commitment_hash.",
    )
    hsm_key_id = models.CharField(max_length=100, blank=True, default="")
    s22_receipt = models.JSONField(
        null=True, blank=True,
        help_text="JSON receipt returned by System 22 on successful ingest.",
    )
    submitted_to_s22_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(
        max_length=15, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True,
    )
    retry_count = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "audit_dailycommitment"
        ordering = ["-date"]
        verbose_name = "Daily Commitment"
        indexes = [models.Index(fields=["date", "status"])]

    def __str__(self):
        return f"Commitment({self.date.isoformat()}, {self.status}) → {self.commitment_hash[:12]}…"


class ExportRequest(models.Model):
    """Auditor-General signed export bundle request.

    Rate-limited to ``EVS_EXPORT_RATE_LIMIT_PER_DAY`` per actor per day.
    Requires step-up MFA (``X-MFA-Verified: true``) at the API layer.
    The async task ``run_auditor_general_export`` builds and signs the ZIP bundle.
    """

    STATUS_PENDING = "pending"
    STATUS_BUILDING = "building"
    STATUS_SIGNED = "signed"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending — queued for async processing"),
        (STATUS_BUILDING, "Building — assembling export bundle"),
        (STATUS_SIGNED, "Signed — bundle ready for download"),
        (STATUS_FAILED, "Failed — see error_detail"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    actor_id = models.UUIDField(db_index=True, help_text="UserProfile.id of the requesting auditor.")
    date_from = models.DateField()
    date_to = models.DateField()
    institution_id = models.UUIDField(
        null=True, blank=True, db_index=True,
        help_text="Optional filter: limit export to a single institution.",
    )
    status = models.CharField(
        max_length=15, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True,
    )
    signed_bundle_url = models.TextField(
        blank=True, default="",
        help_text="Pre-signed MinIO URL for the ZIP bundle (TTL: EVS_EXPORT_URL_TTL_SECONDS).",
    )
    bundle_hash = models.CharField(
        max_length=64, blank=True, default="",
        help_text="SHA-256 hex of the ZIP bundle.",
    )
    hsm_signature = models.TextField(
        blank=True, default="",
        help_text="Base64-encoded HSM signature over bundle_hash.",
    )
    hsm_key_id = models.CharField(max_length=100, blank=True, default="")
    signed_at = models.DateTimeField(null=True, blank=True)
    error_detail = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        db_table = "audit_exportrequest"
        ordering = ["-created_at"]
        verbose_name = "Export Request"
        indexes = [
            models.Index(fields=["actor_id", "created_at"]),
            models.Index(fields=["status", "created_at"]),
        ]

    def __str__(self):
        return f"Export({self.date_from}→{self.date_to}, {self.status})"


class RetentionTierLog(models.Model):
    """Records each hot→warm or warm→cold audit log migration run.

    The async task ``run_tiered_retention_migration`` writes one entry per run.
    Events are never deleted — they are moved to MinIO and flagged with
    ``tier`` field on ``AuditEvent`` (added via migration separately).
    """

    TRANSITION_HOT_WARM = "hot_warm"
    TRANSITION_WARM_COLD = "warm_cold"
    TRANSITION_CHOICES = [
        (TRANSITION_HOT_WARM, "Hot → Warm (90-day threshold)"),
        (TRANSITION_WARM_COLD, "Warm → Cold (3-year threshold)"),
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
    tier_transition = models.CharField(max_length=15, choices=TRANSITION_CHOICES, db_index=True)
    run_date = models.DateField(db_index=True)
    event_count = models.PositiveIntegerField(default=0)
    manifest_hash = models.CharField(
        max_length=64, blank=True, default="",
        help_text="SHA-256 of the migrated JSONL archive file.",
    )
    hsm_signature = models.TextField(blank=True, default="")
    hsm_key_id = models.CharField(max_length=100, blank=True, default="")
    archive_path = models.CharField(
        max_length=500, blank=True, default="",
        help_text="MinIO object key of the compressed JSONL archive.",
    )
    status = models.CharField(
        max_length=15, choices=STATUS_CHOICES, default=STATUS_RUNNING, db_index=True,
    )
    error_detail = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "audit_retentiontierlog"
        ordering = ["-run_date"]
        verbose_name = "Retention Tier Log"

    def __str__(self):
        return f"RetentionMigration({self.tier_transition}, {self.run_date}, {self.status})"


# ── Phase 10 Models ───────────────────────────────────────────────────────────


class GoLiveGate(models.Model):
    """Go-live readiness gate checklist item.

    Each gate corresponds to one Phase 10 readiness criterion (e.g. DR drill passed,
    UAT sign-off, NFR SLO baseline established). All gates must reach ``signed_off``
    before the cutover runbook is unlocked.
    """

    STATUS_OPEN = "open"
    STATUS_SIGNED_OFF = "signed_off"
    STATUS_CHOICES = [
        (STATUS_OPEN, "Open — not yet signed off"),
        (STATUS_SIGNED_OFF, "Signed Off"),
    ]

    gate_id = models.SlugField(max_length=80, unique=True, db_index=True,
        help_text="Machine-readable gate identifier, e.g. 'dr-failover-passed'.")
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, default="")
    owner_role = models.CharField(max_length=80, blank=True, default="",
        help_text="IAM role name responsible for signing off this gate.")
    status = models.CharField(
        max_length=15, choices=STATUS_CHOICES, default=STATUS_OPEN, db_index=True,
    )
    signed_off_by = models.UUIDField(null=True, blank=True,
        help_text="UserProfile.id of the sign-off authority.")
    signed_off_at = models.DateTimeField(null=True, blank=True)
    evidence = models.JSONField(
        default=dict, blank=True,
        help_text="Structured evidence attached at sign-off (test results, report URLs, etc.).",
    )
    display_order = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "audit_golivegate"
        ordering = ["display_order", "gate_id"]
        verbose_name = "Go-Live Gate"

    def __str__(self):
        return f"Gate({self.gate_id}, {self.status})"

    @classmethod
    def all_signed_off(cls) -> bool:
        """Return True only when every gate has been signed off."""
        return not cls.objects.filter(status=cls.STATUS_OPEN).exists()


class DRDrill(models.Model):
    """Disaster Recovery drill record.

    Captures measured RTO/RPO for each drill type so the programme team
    can assert conformance with the ≤4 h RTO / ≤1 h RPO NFR targets.
    """

    TYPE_FAILOVER = "failover"
    TYPE_BACKUP_RESTORE = "backup_restore"
    TYPE_NETWORK_PARTITION = "network_partition"
    DRILL_TYPES = [
        (TYPE_FAILOVER, "Database Failover"),
        (TYPE_BACKUP_RESTORE, "Backup Restore"),
        (TYPE_NETWORK_PARTITION, "Network Partition"),
    ]

    RTO_TARGET_SECONDS = 4 * 3600   # 4 hours
    RPO_TARGET_SECONDS = 1 * 3600   # 1 hour

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    drill_type = models.CharField(max_length=25, choices=DRILL_TYPES, db_index=True)
    started_at = models.DateTimeField(db_index=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    rto_seconds = models.PositiveIntegerField(
        null=True, blank=True,
        help_text="Measured Recovery Time Objective in seconds (target ≤ 14 400).",
    )
    rpo_seconds = models.PositiveIntegerField(
        null=True, blank=True,
        help_text="Measured Recovery Point Objective in seconds (target ≤ 3 600).",
    )
    passed = models.BooleanField(
        null=True, blank=True,
        help_text="True if both RTO and RPO targets were met.",
    )
    notes = models.TextField(blank=True, default="")
    triggered_by = models.UUIDField(null=True, blank=True,
        help_text="UserProfile.id of the drill operator.")
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "audit_drdrill"
        ordering = ["-started_at"]
        verbose_name = "DR Drill"

    def __str__(self):
        status = "PASS" if self.passed else ("FAIL" if self.passed is False else "PENDING")
        return f"DRDrill({self.drill_type}, {self.started_at.date()}, {status})"

    def evaluate_pass(self) -> bool:
        """Evaluate and persist the pass/fail result against NFR targets."""
        if self.rto_seconds is None or self.rpo_seconds is None:
            return False
        self.passed = (
            self.rto_seconds <= self.RTO_TARGET_SECONDS
            and self.rpo_seconds <= self.RPO_TARGET_SECONDS
        )
        self.save(update_fields=["passed"])
        return self.passed
