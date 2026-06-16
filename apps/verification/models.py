"""Verification models — QR scan channel (Phase 3)."""
import uuid

from django.db import models
from django.utils import timezone


class VerificationSession(models.Model):
    """One QR verification attempt.

    Retained 10 years per statutory requirement EVS-N02.
    `result_id` is the stable external identifier surfaced in API responses.
    """

    RESULT_VERIFIED = "verified"
    RESULT_REVOKED = "revoked"
    RESULT_QUARANTINED = "quarantined"
    RESULT_NOT_FOUND = "not_found"
    RESULT_TAMPERED = "tampered"
    RESULT_TOKEN_INVALID = "token_invalid"
    RESULT_TOKEN_EXPIRED = "token_expired"
    RESULT_CHOICES = [
        (RESULT_VERIFIED, "Verified"),
        (RESULT_REVOKED, "Revoked"),
        (RESULT_QUARANTINED, "Quarantined"),
        (RESULT_NOT_FOUND, "Not Found"),
        (RESULT_TAMPERED, "Tampered — integrity failure"),
        (RESULT_TOKEN_INVALID, "Token Invalid"),
        (RESULT_TOKEN_EXPIRED, "Token Expired"),
    ]

    CHANNEL_QR_SCAN = "qr_scan"
    CHANNEL_API = "api"
    CHANNEL_CHOICES = [
        (CHANNEL_QR_SCAN, "QR Scan"),
        (CHANNEL_API, "API"),
    ]

    id = models.BigAutoField(primary_key=True)
    result_id = models.UUIDField(
        default=uuid.uuid4, unique=True, db_index=True, editable=False,
        help_text="Stable external identifier — used in GET /v1/verify/results/{result_id}.",
    )
    credential_id_claimed = models.UUIDField(
        db_index=True,
        help_text="The UUID from the URL path — not yet validated at record creation.",
    )
    credential = models.ForeignKey(
        "registry.Credential",
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name="verification_sessions",
        help_text="Null when the credential was not found or token was invalid.",
    )
    result = models.CharField(max_length=20, choices=RESULT_CHOICES, db_index=True)
    channel = models.CharField(
        max_length=30, choices=CHANNEL_CHOICES, default=CHANNEL_QR_SCAN,
        help_text="Scan channel: qr_scan (camera) or api (programmatic).",
    )
    verifier_ip = models.GenericIPAddressField(null=True, blank=True)
    verifier_user_agent = models.TextField(blank=True)
    device_fingerprint = models.CharField(max_length=255, blank=True,
        help_text="Client-supplied device fingerprint for fraud correlation.")
    verifier_id = models.UUIDField(null=True, blank=True, db_index=True,
        help_text="UserProfile.id if the verifier was authenticated.")
    jwt_kid = models.CharField(max_length=100, blank=True,
        help_text="Key ID from the QR JWT header.")
    payload_hash = models.CharField(max_length=64, blank=True,
        help_text="SHA-256 hex of the raw JWT token string.")
    checks_performed = models.JSONField(default=list,
        help_text="Ordered list of check names that ran before the result was reached.")
    audit_chain_ref = models.CharField(max_length=64, blank=True,
        help_text="chain_hash of the AuditEvent written for this session (async-filled).")
    latency_ms = models.PositiveIntegerField(null=True, blank=True,
        help_text="End-to-end verification latency in milliseconds. Target: ≤2000 ms.")
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        db_table = "verification_verificationsession"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["result", "created_at"]),
            models.Index(fields=["credential_id_claimed", "created_at"]),
        ]

    def __str__(self):
        return f"Verify({self.credential_id_claimed})[{self.channel}] → {self.result}"
