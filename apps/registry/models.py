"""EVS credential registry — the central verified-credential store."""
import uuid

from django.db import models
from django.utils import timezone


class CredentialSchemaVersion(models.Model):
    """Versioned JSON Schema for credential payloads.

    Each schema_id (e.g. "gsl-llb") can have multiple versions; only one
    is active at a time for ingest. Old versions remain attached to existing
    credentials for integrity verification.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    schema_id = models.CharField(max_length=100, db_index=True,
        help_text="Logical schema name, e.g. 'gsl-llb', 'gsl-bl'.")
    version = models.PositiveIntegerField(default=1)
    label = models.CharField(max_length=255, blank=True,
        help_text="Human-readable label, e.g. 'GSL LLB 2024'.")
    schema_json = models.JSONField(
        help_text="JSON Schema (draft-07) used to validate credential payloads.")
    required_fields = models.JSONField(default=list,
        help_text="Ordered list of field names that must be present in every record.")
    is_active = models.BooleanField(default=True, db_index=True)
    deprecated_at = models.DateTimeField(null=True, blank=True,
        help_text="When this schema version was deprecated; NULL = still current.")
    created_by = models.UUIDField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "registry_credentialschemaversion"
        unique_together = [("schema_id", "version")]
        ordering = ["schema_id", "-version"]

    def __str__(self):
        return f"{self.schema_id} v{self.version}"


class Credential(models.Model):
    """A verified credential record — the core EVS artifact.

    Immutable once written (status transitions are the only mutations).
    SHA-256 hash of the canonical payload is the tamper-evidence anchor.
    Typed PII columns are indexed for NLEMS/NBES queries; the full payload
    JSONB field is the source-of-truth for hash computation.
    10-year statutory retention (EVS-N02).
    """

    STATUS_ACTIVE = "active"
    STATUS_REVOKED = "revoked"
    STATUS_QUARANTINED = "quarantined"
    STATUS_SUSPENDED = "suspended"
    STATUS_CHOICES = [
        (STATUS_ACTIVE, "Active"),
        (STATUS_REVOKED, "Revoked"),
        (STATUS_QUARANTINED, "Quarantined — under review"),
        (STATUS_SUSPENDED, "Suspended — migration rollback or hold"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    credential_ref = models.CharField(max_length=150, unique=True, db_index=True,
        help_text="Human-readable reference, e.g. GSL/2024/LLB/001234.")
    schema_version = models.ForeignKey(
        CredentialSchemaVersion, on_delete=models.PROTECT, related_name="credentials",
        null=True, blank=True,
        help_text="Null for legacy-migrated credentials that predate the schema registry.",
    )
    institution_id = models.UUIDField(db_index=True,
        help_text="InstitutionMaster.id — FK enforced at application layer (cross-app).")
    graduation_cycle_id = models.UUIDField(null=True, blank=True, db_index=True,
        help_text="GraduationCycle.id — FK enforced at application layer.")
    candidate_id = models.UUIDField(null=True, blank=True, db_index=True,
        help_text="UserProfile.id if the candidate has an EVS account.")

    # ── Typed PII columns (SRS §4.2) — duplicated from payload for indexed queries ──
    student_full_name = models.CharField(max_length=300, blank=True, db_index=True)
    date_of_birth = models.DateField(null=True, blank=True)
    waec_index = models.CharField(max_length=50, blank=True, db_index=True)
    llb_award_date = models.DateField(null=True, blank=True)
    institution_code = models.CharField(max_length=20, blank=True, db_index=True)
    graduate_index_number = models.CharField(max_length=100, blank=True, db_index=True)
    degree_classification = models.CharField(max_length=50, blank=True)
    programme_code = models.CharField(max_length=50, blank=True, db_index=True)

    payload = models.JSONField(
        help_text="Canonical credential payload (sorted keys, NFC strings).")
    sha256_hash = models.CharField(max_length=64, unique=True, db_index=True,
        help_text="SHA-256 hex of canonical JSON payload — tamper evidence anchor.")
    qr_payload = models.TextField(blank=True,
        help_text="Signed JWT embedded in the QR code.")
    qr_url = models.URLField(max_length=500, blank=True,
        help_text="https://evs.clet.gov.gh/verify/<uuid>?token=<jwt>")
    status = models.CharField(
        max_length=15, choices=STATUS_CHOICES, default=STATUS_ACTIVE, db_index=True,
    )
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoke_reason = models.TextField(blank=True)
    revoked_by = models.UUIDField(null=True, blank=True)
    batch_id = models.UUIDField(null=True, blank=True, db_index=True,
        help_text="BatchIngest.id that created this record.")
    legacy = models.BooleanField(default=False, db_index=True,
        help_text="True if migrated from a legacy system (Phase 8).")
    wave_id = models.UUIDField(null=True, blank=True, db_index=True,
        help_text="MigrationWave.id — set only for legacy credentials.")
    integrity_checked_at = models.DateTimeField(null=True, blank=True)
    integrity_ok = models.BooleanField(null=True, blank=True,
        help_text="Set by the nightly integrity sweep task.")
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "registry_credential"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["institution_id", "status"]),
            models.Index(fields=["graduation_cycle_id", "status"]),
            models.Index(fields=["candidate_id"]),
            models.Index(fields=["integrity_ok", "status"]),
            models.Index(fields=["graduate_index_number"]),
        ]

    def __str__(self):
        return f"{self.credential_ref} [{self.status}]"


class BatchIngest(models.Model):
    """Tracks a credential batch ingest job submitted by an institution officer.

    Max 10,000 records per batch, 100 MB file size limit.
    Partial-success: valid records are registered; failures are reported per-row.
    """

    STATUS_PENDING = "pending"
    STATUS_PROCESSING = "processing"
    STATUS_COMPLETED = "completed"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_PROCESSING, "Processing"),
        (STATUS_COMPLETED, "Completed"),
        (STATUS_FAILED, "Failed"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    transaction_id = models.UUIDField(unique=True, default=uuid.uuid4, db_index=True,
        help_text="Externally-visible idempotency key for this batch transaction.")
    institution_id = models.UUIDField(db_index=True)
    graduation_cycle_id = models.UUIDField(null=True, blank=True, db_index=True)
    schema_version = models.ForeignKey(
        CredentialSchemaVersion, on_delete=models.PROTECT, related_name="batch_ingests",
    )
    submitted_by = models.UUIDField(null=True, blank=True,
        help_text="UserProfile.id of the institution officer.")
    original_filename = models.CharField(max_length=255)
    file_hash = models.CharField(max_length=64, help_text="SHA-256 hex of the uploaded file.")
    file_format = models.CharField(max_length=10, default="json",
        choices=[("json", "JSON"), ("csv", "CSV")])
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True,
    )
    total_records = models.PositiveIntegerField(default=0)
    success_count = models.PositiveIntegerField(default=0)
    failure_count = models.PositiveIntegerField(default=0)
    row_errors = models.JSONField(default=list,
        help_text="List of {row, ref, error} for each failed record.")
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "registry_batchingest"
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["institution_id", "status"])]

    def __str__(self):
        return f"Batch({self.original_filename}, {self.status})"


class RevocationRecord(models.Model):
    """Append-only revocation log. Referenced by verification service."""

    SOURCE_CONFIRMED_FRAUD = "confirmed_fraud"
    SOURCE_ADMIN = "admin"
    SOURCE_DG = "dg"
    SOURCE_CHOICES = [
        (SOURCE_CONFIRMED_FRAUD, "Confirmed Fraud"),
        (SOURCE_ADMIN, "Administrative"),
        (SOURCE_DG, "Director-General Order"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    credential = models.ForeignKey(
        Credential, on_delete=models.CASCADE, related_name="revocations",
    )
    revoked_by = models.UUIDField(help_text="UserProfile.id of the revoking officer.")
    reason = models.TextField()
    source = models.CharField(
        max_length=20, choices=SOURCE_CHOICES, default=SOURCE_ADMIN,
        help_text="Authority under which the revocation was issued.",
    )
    signature_ref = models.CharField(max_length=255, blank=True,
        help_text="HSM signature token (kid:token) from the DG-sign step.")
    revoked_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        db_table = "registry_revocationrecord"
        ordering = ["-revoked_at"]

    def __str__(self):
        return f"Revoked({self.credential.credential_ref}) @ {self.revoked_at.date()}"


class IntegrityRun(models.Model):
    """Records each execution of the nightly integrity sweep (EVS-N05)."""

    STATUS_RUNNING = "running"
    STATUS_COMPLETED = "completed"
    STATUS_FAILED = "failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    started_at = models.DateTimeField(default=timezone.now, db_index=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    records_checked = models.PositiveIntegerField(default=0)
    tampered_count = models.PositiveIntegerField(default=0)
    tampered_ids = models.JSONField(default=list,
        help_text="UUIDs of credentials found tampered (capped at 100 for storage).")
    anchor_hash = models.CharField(max_length=64, blank=True,
        help_text="chain_hash of the AuditEvent written for this sweep.")
    status = models.CharField(max_length=20, default=STATUS_RUNNING)

    class Meta:
        db_table = "registry_integrityrun"
        ordering = ["-started_at"]

    def __str__(self):
        return f"IntegrityRun {self.started_at.date()} checked={self.records_checked} tampered={self.tampered_count}"
