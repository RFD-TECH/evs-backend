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

        # Hash covers all forensically relevant fields (EVS-N01).
        payload = json.dumps(
            {
                "event_id": str(event_id),
                "actor_id": str(kwargs.get("actor_id", "")),
                "action": action,
                "entity_type": kwargs.get("entity_type", ""),
                "entity_id": str(kwargs.get("entity_id", "")),
                "old_state": kwargs.get("old_state") or {},
                "new_state": kwargs.get("new_state") or {},
                "ip_address": str(kwargs.get("ip_address") or ""),
                "user_agent": str(kwargs.get("user_agent") or ""),
                "request_id": str(kwargs.get("request_id") or ""),
                "source_system": str(kwargs.get("source_system") or "evs"),
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

        # Relay to CALS via outbox — the Celery poller forwards to System 17 asynchronously.
        from shared.events import publish
        publish(
            "AuditEventRecorded",
            {
                "event_id": str(event.event_id),
                "chain_hash": chain_hash,
                "action": action,
                "entity_type": kwargs.get("entity_type", ""),
                "entity_id": str(kwargs.get("entity_id") or ""),
                "actor_id": str(kwargs.get("actor_id") or ""),
                "previous_hash": previous_hash,
            },
            topic="evs.audit",
        )

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
