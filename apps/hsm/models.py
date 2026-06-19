"""HSM key registry — public key metadata only. Private keys never leave the HSM."""
import uuid

from django.db import models


class HsmKey(models.Model):
    ALGORITHM_CHOICES = [
        ("ES256", "ES256 — ECDSA P-256"),
        ("RS256", "RS256 — RSA-PKCS1v1.5 2048"),
        ("EdDSA", "EdDSA — Ed25519"),
        ("HS256", "HS256 — HMAC-SHA256 (dev only)"),
    ]
    PURPOSE_CHOICES = [
        ("qr_jwt_sign", "QR JWT Signing"),
        ("dg_sign", "Director-General Credential Signing"),
        ("credential_sign", "Credential Batch Signing"),
        ("revocation_list_integrity", "Revocation List Integrity"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    kid = models.CharField(max_length=100, unique=True, db_index=True,
        help_text="Key identifier — included in JWT header and JWKS response.")
    algorithm = models.CharField(max_length=10, choices=ALGORITHM_CHOICES)
    purpose = models.CharField(max_length=20, choices=PURPOSE_CHOICES, db_index=True)
    public_key_pem = models.TextField(
        blank=True,
        help_text="PEM-encoded public key (stored here; private key stays in HSM/env).",
    )
    is_active = models.BooleanField(default=True, db_index=True)
    valid_from = models.DateTimeField()
    valid_until = models.DateTimeField(null=True, blank=True,
        help_text="Null = no expiry defined at creation time.")
    rotated_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "hsm_hsmkey"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.kid} ({self.algorithm}, {self.purpose})"
