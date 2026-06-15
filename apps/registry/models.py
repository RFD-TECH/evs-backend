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

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    credential = models.ForeignKey(
        Credential, on_delete=models.CASCADE, related_name="revocations",
    )
    revoked_by = models.UUIDField(help_text="UserProfile.id of the revoking officer.")
    reason = models.TextField()
    revoked_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        db_table = "registry_revocationrecord"
        ordering = ["-revoked_at"]

    def __str__(self):
        return f"Revoked({self.credential.credential_ref}) @ {self.revoked_at.date()}"


# ── Phase 9 Models ────────────────────────────────────────────────────────────


class IntegrityRun(models.Model):
    """Persistent record of each nightly (or manual) credential integrity sweep.

    The sweep task writes one ``IntegrityRun`` per execution. The ``checkpoint_state``
    JSON field stores the last-processed credential PK so that a crashed sweep can
    resume from where it stopped rather than restarting from the beginning.

    After a successful run, ``merkle_root`` contains the SHA-256 of all
    ``"{id}:{sha256_hash}"`` pairs sorted by credential UUID, providing a single
    cryptographic fingerprint over the entire active credential corpus.
    """

    STATUS_RUNNING = "running"
    STATUS_COMPLETED = "completed"
    STATUS_PARTIAL = "partial"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_RUNNING, "Running — sweep in progress"),
        (STATUS_COMPLETED, "Completed — all credentials checked"),
        (STATUS_PARTIAL, "Partial — sweep interrupted; checkpoint saved"),
        (STATUS_FAILED, "Failed — unrecoverable error"),
    ]

    SWEEP_SCHEDULED = "scheduled"
    SWEEP_MANUAL = "manual"
    SWEEP_TYPES = [
        (SWEEP_SCHEDULED, "Scheduled — triggered by Celery beat"),
        (SWEEP_MANUAL, "Manual — triggered via API"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sweep_type = models.CharField(max_length=12, choices=SWEEP_TYPES, default=SWEEP_SCHEDULED, db_index=True)
    started_at = models.DateTimeField(default=timezone.now, db_index=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    total_checked = models.PositiveIntegerField(default=0)
    tampered_count = models.PositiveIntegerField(default=0)
    merkle_root = models.CharField(
        max_length=64, blank=True, default="",
        help_text="SHA-256 of all '{uuid}:{sha256}' pairs sorted by credential UUID.",
    )
    hsm_signature = models.TextField(
        blank=True, default="",
        help_text="Base64-encoded HSM signature over merkle_root.",
    )
    hsm_key_id = models.CharField(max_length=100, blank=True, default="")
    status = models.CharField(
        max_length=12, choices=STATUS_CHOICES, default=STATUS_RUNNING, db_index=True,
    )
    checkpoint_state = models.JSONField(
        default=dict, blank=True,
        help_text="Crash-recovery state — stores {'last_id': '<uuid>', 'checked': N, 'tampered': N}.",
    )
    triggered_by = models.UUIDField(
        null=True, blank=True,
        help_text="UserProfile.id — set for manual runs only.",
    )
    error_detail = models.TextField(blank=True, default="")

    class Meta:
        db_table = "registry_integrityrun"
        ordering = ["-started_at"]
        verbose_name = "Integrity Run"
        indexes = [
            models.Index(fields=["status", "started_at"]),
            models.Index(fields=["sweep_type", "started_at"]),
        ]

    def __str__(self):
        return f"IntegrityRun({self.sweep_type}, {self.started_at.date()}, {self.status})"
