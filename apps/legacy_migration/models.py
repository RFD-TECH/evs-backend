"""Legacy Data Migration models — Phase 8 (EVS-F09).

Key invariants:
- Rollback never deletes: it sets wave status to RolledBack/Quarantined and preserves all records.
- Legacy credentials receive the same UUID, SHA-256 hash, and QR payload as new awards.
- Verification path is identical: verifiers cannot distinguish legacy from contemporary records.
- Institution must confirm each record within the 14-day window or it is flagged for manual review.
- Pre-go-live audit report is dual-signed (Admin + Registrar) and anchored to System 22.
"""
import uuid

from django.db import models
from django.utils import timezone


class MigrationWave(models.Model):
    """A named cohort of legacy records migrated together (EVS-F09-01).

    State machine: Planned → Active → Live → (RolledBack | Quarantined)
    Rollback transitions preserve all data; they never delete credentials.
    """

    STATUS_PLANNED = "planned"
    STATUS_ACTIVE = "active"
    STATUS_LIVE = "live"
    STATUS_ROLLED_BACK = "rolled_back"
    STATUS_QUARANTINED = "quarantined"
    STATUS_CHOICES = [
        (STATUS_PLANNED, "Planned"),
        (STATUS_ACTIVE, "Active — ingesting"),
        (STATUS_LIVE, "Live — fully confirmed and published"),
        (STATUS_ROLLED_BACK, "Rolled Back"),
        (STATUS_QUARANTINED, "Quarantined — compliance hold"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True,
        help_text="Human-readable wave identifier, e.g. 'KNUST-2010-2015'.")
    description = models.TextField(blank=True)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default=STATUS_PLANNED, db_index=True)
    institution_id = models.UUIDField(db_index=True,
        help_text="Institution whose historical records this wave covers.")
    graduation_year_from = models.PositiveSmallIntegerField(null=True, blank=True)
    graduation_year_to = models.PositiveSmallIntegerField(null=True, blank=True)
    confirmation_deadline = models.DateTimeField(
        help_text="Institution must confirm all records before this deadline (14-day window).")
    activated_at = models.DateTimeField(null=True, blank=True)
    activated_by = models.UUIDField(null=True, blank=True)
    went_live_at = models.DateTimeField(null=True, blank=True)
    went_live_by = models.UUIDField(null=True, blank=True)
    rolled_back_at = models.DateTimeField(null=True, blank=True)
    rolled_back_by = models.UUIDField(null=True, blank=True)
    rollback_reason = models.TextField(blank=True)
    quarantined_at = models.DateTimeField(null=True, blank=True)
    quarantine_reason = models.TextField(blank=True)
    created_by = models.UUIDField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "legacy_migrationwave"
        ordering = ["-created_at"]

    def __str__(self):
        return f"Wave({self.name})[{self.status}]"

    @property
    def is_terminal(self):
        return self.status in (self.STATUS_ROLLED_BACK, self.STATUS_QUARANTINED)


class LegacyBatch(models.Model):
    """A single batch file upload within a MigrationWave (EVS-F09-02).

    Each batch corresponds to one CSV/Excel/JSON upload by an institution officer.
    After upload the system ingests row by row and creates Credentials with legacy=True.
    """

    STATUS_PENDING = "pending"
    STATUS_PROCESSING = "processing"
    STATUS_AWAITING_CONFIRMATION = "awaiting_confirmation"
    STATUS_CONFIRMED = "confirmed"
    STATUS_REJECTED = "rejected"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_PROCESSING, "Processing"),
        (STATUS_AWAITING_CONFIRMATION, "Awaiting Institution Confirmation"),
        (STATUS_CONFIRMED, "Confirmed"),
        (STATUS_REJECTED, "Rejected"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    wave = models.ForeignKey(MigrationWave, on_delete=models.PROTECT, related_name="batches")
    batch_ref = models.CharField(max_length=100, unique=True,
        help_text="EVS-generated batch reference for the institution officer.")
    uploaded_by = models.UUIDField(help_text="keycloak_sub of the institution officer.")
    file_name = models.CharField(max_length=500)
    file_sha256 = models.CharField(max_length=64,
        help_text="SHA-256 of the uploaded file — immutable once set.")
    record_count = models.PositiveIntegerField(default=0)
    ingested_count = models.PositiveIntegerField(default=0)
    confirmed_count = models.PositiveIntegerField(default=0)
    rejected_count = models.PositiveIntegerField(default=0)
    status = models.CharField(max_length=25, choices=STATUS_CHOICES,
                              default=STATUS_PENDING, db_index=True)
    affidavit_ref = models.CharField(max_length=255, blank=True,
        help_text="Reference to the notarised institution affidavit (F09-02 requirement).")
    affidavit_verified = models.BooleanField(default=False,
        help_text="Registrar must verify affidavit before batch may proceed to Live.")
    error_summary = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "legacy_legacybatch"
        ordering = ["-created_at"]

    def __str__(self):
        return f"LegacyBatch({self.batch_ref})[{self.status}]"


class LegacyConfirmation(models.Model):
    """Per-record confirmation by the institution during the 14-day window (EVS-F09-03).

    Institutions confirm or reject each credential one by one. A record that is
    neither confirmed nor rejected before the deadline is flagged for manual review.
    """

    DECISION_CONFIRMED = "confirmed"
    DECISION_REJECTED = "rejected"
    DECISION_CHOICES = [
        (DECISION_CONFIRMED, "Confirmed"),
        (DECISION_REJECTED, "Rejected"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    batch = models.ForeignKey(LegacyBatch, on_delete=models.PROTECT, related_name="confirmations")
    credential_id = models.UUIDField(db_index=True,
        help_text="Credential.id of the legacy record being confirmed.")
    decision = models.CharField(max_length=10, choices=DECISION_CHOICES, db_index=True)
    decided_by = models.UUIDField(help_text="keycloak_sub of the institution officer.")
    decided_at = models.DateTimeField(default=timezone.now, db_index=True)
    rejection_reason = models.TextField(blank=True)
    audit_hash = models.CharField(max_length=64, blank=True)

    class Meta:
        db_table = "legacy_legacyconfirmation"
        unique_together = [("batch", "credential_id")]
        ordering = ["-decided_at"]

    def __str__(self):
        return f"Confirmation({self.credential_id})[{self.decision}]"


class CredentialVersion(models.Model):
    """Immutable snapshot of a Credential at a point in time (EVS-F09-04).

    Created whenever a credential's payload changes materially — e.g. during
    ingest error correction or a post-confirmation amendment. Version 1 is the
    original ingest; each subsequent correction increments the version counter.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    credential_id = models.UUIDField(db_index=True,
        help_text="Credential.id this version belongs to.")
    version = models.PositiveIntegerField(
        help_text="Monotonically increasing version number (1 = original).")
    payload_snapshot = models.JSONField(
        help_text="Complete payload dict at this version.")
    sha256_at_version = models.CharField(max_length=64)
    changed_by = models.UUIDField(null=True, blank=True,
        help_text="Actor who caused this version to be created.")
    change_reason = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        db_table = "legacy_credentialversion"
        unique_together = [("credential_id", "version")]
        ordering = ["credential_id", "version"]

    def __str__(self):
        return f"CredVer({self.credential_id}@v{self.version})"


class MigrationAuditReport(models.Model):
    """Dual-signed pre-go-live audit report (EVS-F09-06).

    Must be generated and signed by both an Administrator and a Registrar
    before a wave may transition to Live status. Once signed it is immutable.
    Anchored to System 22 within 1 second of creation.
    """

    STATUS_DRAFT = "draft"
    STATUS_ADMIN_SIGNED = "admin_signed"
    STATUS_FULLY_SIGNED = "fully_signed"
    STATUS_CHOICES = [
        (STATUS_DRAFT, "Draft"),
        (STATUS_ADMIN_SIGNED, "Admin Signed — awaiting Registrar"),
        (STATUS_FULLY_SIGNED, "Fully Signed — ready for go-live"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    wave = models.OneToOneField(MigrationWave, on_delete=models.PROTECT, related_name="audit_report")
    status = models.CharField(max_length=15, choices=STATUS_CHOICES,
                              default=STATUS_DRAFT, db_index=True)
    report_payload = models.JSONField(default=dict,
        help_text="Full report content: counts, parity checks, anomaly summary.")
    admin_signer_id = models.UUIDField(null=True, blank=True)
    admin_signed_at = models.DateTimeField(null=True, blank=True)
    admin_signature_hash = models.CharField(max_length=64, blank=True)
    registrar_signer_id = models.UUIDField(null=True, blank=True)
    registrar_signed_at = models.DateTimeField(null=True, blank=True)
    registrar_signature_hash = models.CharField(max_length=64, blank=True)
    audit_chain_ref = models.CharField(max_length=100, blank=True,
        help_text="System 22 AuditEvent.id for the final dual-signed state.")
    generated_at = models.DateTimeField(default=timezone.now)
    generated_by = models.UUIDField(null=True, blank=True)

    class Meta:
        db_table = "legacy_migrationauditreport"
        ordering = ["-generated_at"]

    def __str__(self):
        return f"AuditReport(wave={self.wave_id})[{self.status}]"

    @property
    def is_fully_signed(self):
        return self.status == self.STATUS_FULLY_SIGNED
