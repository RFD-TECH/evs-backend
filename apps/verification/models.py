"""Verification models — all four channels share the same session log.

Phase 3: QR scan (real-time).
Phase 4: PDF (PAdES signature) + Uploaded-QR (image/PDF decode).
Phase 5: WAEC + Faculty connectors.
"""
import uuid

from django.db import models
from django.utils import timezone


class TrustAnchor(models.Model):
    """Certificate Authority trusted for PDF signature validation (F06-03).

    Managed by System Administrators; changes are audit-logged via the outbox.
    """

    STATUS_ACTIVE = "active"
    STATUS_EXPIRED = "expired"
    STATUS_REVOKED = "revoked"
    STATUS_CHOICES = [
        (STATUS_ACTIVE, "Active"),
        (STATUS_EXPIRED, "Expired"),
        (STATUS_REVOKED, "Revoked"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ca_name = models.CharField(max_length=255)
    ca_certificate_pem = models.TextField(help_text="PEM-encoded CA certificate.")
    ocsp_endpoint = models.URLField(blank=True)
    crl_endpoint = models.URLField(blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_ACTIVE, db_index=True)
    added_by = models.UUIDField(null=True, blank=True, help_text="keycloak_sub of the Administrator.")
    added_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    signed_change_ref = models.CharField(max_length=100, blank=True,
        help_text="AuditEvent id of the signed configuration-change record.")

    class Meta:
        db_table = "verification_trustanchor"
        ordering = ["ca_name"]

    def __str__(self):
        return f"{self.ca_name} [{self.status}]"


class DocumentVaultObject(models.Model):
    """Content-addressable encrypted blob store for verification artefacts (F06-01).

    Storing by SHA-256 deduplicates uploads naturally; the hash is the FK
    anchor for dispute reconstruction.
    Retention: 10 years per N02.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sha256 = models.CharField(max_length=64, unique=True, db_index=True)
    mime_type = models.CharField(max_length=100)
    byte_size = models.PositiveBigIntegerField()
    uploaded_by = models.UUIDField(null=True, blank=True,
        help_text="keycloak_sub of the Verifier who uploaded the file.")
    uploaded_at = models.DateTimeField(auto_now_add=True)
    retention_until = models.DateField(help_text="File must be preserved until this date.")
    encryption_kid = models.CharField(max_length=100, blank=True,
        help_text="HSM key ID used to encrypt the stored blob.")
    tamper_flag = models.BooleanField(default=False,
        help_text="Set when a verification of this file returned Tampered.")
    original_filename_hash = models.CharField(max_length=64, blank=True,
        help_text="SHA-256 of the original filename (not the file itself); PII-safe.")
    virus_clean = models.BooleanField(default=False,
        help_text="True once the AV scanner returned clean.")

    class Meta:
        db_table = "verification_documentvaultobject"
        ordering = ["-uploaded_at"]

    def __str__(self):
        return f"Vault:{self.sha256[:12]}… ({self.mime_type})"


class VerificationSession(models.Model):
    """One verification attempt, regardless of channel or outcome.

    Retained 10 years per statutory requirement EVS-N02.
    All four channels (QR scan, PDF, Uploaded-QR, WAEC/Faculty) write here.
    """

    RESULT_VERIFIED = "verified"
    RESULT_REVOKED = "revoked"
    RESULT_QUARANTINED = "quarantined"
    RESULT_NOT_FOUND = "not_found"
    RESULT_TAMPERED = "tampered"
    RESULT_TOKEN_INVALID = "token_invalid"
    RESULT_TOKEN_EXPIRED = "token_expired"
    RESULT_INVALID_SIGNATURE = "invalid_signature"
    RESULT_UNTRUSTED_ISSUER = "untrusted_issuer"
    RESULT_INVALID_QR = "invalid_qr"
    RESULT_MANUAL_PENDING = "manual_pending"
    RESULT_CHOICES = [
        (RESULT_VERIFIED, "Verified"),
        (RESULT_REVOKED, "Revoked"),
        (RESULT_QUARANTINED, "Quarantined"),
        (RESULT_NOT_FOUND, "Not Found"),
        (RESULT_TAMPERED, "Tampered — integrity failure"),
        (RESULT_TOKEN_INVALID, "Token Invalid"),
        (RESULT_TOKEN_EXPIRED, "Token Expired"),
        (RESULT_INVALID_SIGNATURE, "Invalid Signature"),
        (RESULT_UNTRUSTED_ISSUER, "Untrusted Issuer"),
        (RESULT_INVALID_QR, "Invalid QR Code"),
        (RESULT_MANUAL_PENDING, "Queued for Manual Verification"),
    ]

    CHANNEL_QR_SCAN = "qr_scan"
    CHANNEL_PDF = "pdf"
    CHANNEL_UPLOADED_QR = "uploaded_qr"
    CHANNEL_WAEC = "waec"
    CHANNEL_FACULTY = "faculty"
    CHANNEL_MANUAL = "manual"
    CHANNEL_CHOICES = [
        (CHANNEL_QR_SCAN, "QR Scan"),
        (CHANNEL_PDF, "PDF Upload"),
        (CHANNEL_UPLOADED_QR, "Uploaded-QR"),
        (CHANNEL_WAEC, "WAEC"),
        (CHANNEL_FACULTY, "Faculty Connector"),
        (CHANNEL_MANUAL, "Manual"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    channel = models.CharField(
        max_length=15, choices=CHANNEL_CHOICES, default=CHANNEL_QR_SCAN, db_index=True
    )
    credential_id_claimed = models.UUIDField(db_index=True, null=True, blank=True,
        help_text="The UUID from the URL path or PDF metadata — not yet validated at record creation.")
    credential = models.ForeignKey(
        "registry.Credential",
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name="verification_sessions",
        help_text="Null when the credential was not found or token was invalid.",
    )
    result = models.CharField(max_length=20, choices=RESULT_CHOICES, db_index=True)
    result_detail = models.CharField(max_length=255, blank=True,
        help_text="Machine-readable detail code, e.g. BYTE_RANGE_INTEGRITY_FAILURE.")
    verifier_ip = models.GenericIPAddressField(null=True, blank=True)
    verifier_user_agent = models.TextField(blank=True)
    verifier_id = models.UUIDField(null=True, blank=True, db_index=True,
        help_text="UserProfile.id if the verifier was authenticated.")
    jwt_kid = models.CharField(max_length=100, blank=True,
        help_text="Key ID from the QR JWT header.")
    file_sha256 = models.CharField(max_length=64, blank=True, db_index=True,
        help_text="SHA-256 of uploaded PDF/image; links session to DocumentVaultObject.")
    verification_ms = models.PositiveIntegerField(null=True, blank=True,
        help_text="End-to-end verification latency in milliseconds.")
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        db_table = "verification_verificationsession"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["result", "created_at"]),
            models.Index(fields=["credential_id_claimed", "created_at"]),
            models.Index(fields=["channel", "result", "created_at"]),
            models.Index(fields=["file_sha256"]),
        ]

    def __str__(self):
        cid = str(self.credential_id_claimed) if self.credential_id_claimed else "-"
        return f"Verify({cid})[{self.channel}] → {self.result}"


class PdfSignatureOutcome(models.Model):
    """Per-signature outcome for a PDF verification (F06-02 / F06-03).

    A multi-signature PDF produces multiple rows, all linked to the same
    VerificationSession. If any signature fails, the overall session result
    is invalid_signature or tampered.
    """

    PROFILE_PADES_BT = "pades_bt"
    PROFILE_PADES_BLT = "pades_blt"
    PROFILE_PADES_BLTA = "pades_blta"
    PROFILE_PKCS7 = "pkcs7"
    PROFILE_CHOICES = [
        (PROFILE_PADES_BT, "PAdES B-T"),
        (PROFILE_PADES_BLT, "PAdES B-LT"),
        (PROFILE_PADES_BLTA, "PAdES B-LTA"),
        (PROFILE_PKCS7, "PKCS#7 Detached"),
    ]

    REVOCATION_GOOD = "good"
    REVOCATION_UNKNOWN = "unknown"
    REVOCATION_REVOKED = "revoked"
    REVOCATION_UNCHECKED = "unchecked"
    REVOCATION_CHOICES = [
        (REVOCATION_GOOD, "Good"),
        (REVOCATION_UNKNOWN, "Unknown"),
        (REVOCATION_REVOKED, "Revoked"),
        (REVOCATION_UNCHECKED, "Unchecked — OCSP/CRL unreachable"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    verification_session = models.ForeignKey(
        VerificationSession, on_delete=models.CASCADE, related_name="signature_outcomes"
    )
    signer_subject = models.TextField(help_text="Distinguished Name of the signing certificate.")
    signing_time = models.DateTimeField(null=True, blank=True)
    profile = models.CharField(max_length=15, choices=PROFILE_CHOICES)
    integrity_ok = models.BooleanField(
        help_text="True when the PDF byte-range hash matches the embedded signature.")
    chain_ok = models.BooleanField(
        help_text="True when the certificate chain validates up to a trust anchor.")
    revocation_status = models.CharField(max_length=10, choices=REVOCATION_CHOICES)
    timestamp_ok = models.BooleanField(null=True, blank=True,
        help_text="True when the embedded timestamp token validates. Null for B-T profiles.")
    signer_ca = models.ForeignKey(
        TrustAnchor, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="signature_outcomes",
        help_text="The trust anchor whose chain this signature validated against.",
    )
    failure_reason = models.CharField(max_length=255, blank=True,
        help_text="Machine-readable failure code if any check failed.")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "verification_pdfsignatureoutcome"
        ordering = ["created_at"]

    def __str__(self):
        ok = "OK" if (self.integrity_ok and self.chain_ok) else "FAIL"
        return f"{ok} {self.signer_subject[:40]}…"
