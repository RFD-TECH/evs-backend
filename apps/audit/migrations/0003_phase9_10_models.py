# Generated migration for Phase 9 & 10 audit models.
import django.utils.timezone
import uuid
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("audit", "0002_audit_immutability_trigger"),
    ]

    operations = [
        # ── DailyCommitment ───────────────────────────────────────────────────
        migrations.CreateModel(
            name="DailyCommitment",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("date", models.DateField(db_index=True, unique=True)),
                (
                    "anchor",
                    models.OneToOneField(
                        blank=True,
                        help_text="The DailyHashAnchor that seeds the head_hash for this commitment.",
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="commitment",
                        to="audit.dailyhashanchor",
                    ),
                ),
                (
                    "integrity_merkle_root",
                    models.CharField(
                        blank=True,
                        default="",
                        help_text="SHA-256 Merkle root of all credential {id}:{sha256} pairs from the nightly sweep.",
                        max_length=64,
                    ),
                ),
                (
                    "prev_commitment_hash",
                    models.CharField(
                        help_text="commitment_hash of the previous day's DailyCommitment (or 64× '0' for genesis).",
                        max_length=64,
                    ),
                ),
                (
                    "commitment_hash",
                    models.CharField(
                        db_index=True,
                        help_text="SHA-256(prev_commitment_hash + integrity_merkle_root + head_hash).",
                        max_length=64,
                    ),
                ),
                (
                    "hsm_signature",
                    models.TextField(
                        blank=True,
                        default="",
                        help_text="Base64-encoded HSM signature over commitment_hash.",
                    ),
                ),
                ("hsm_key_id", models.CharField(blank=True, default="", max_length=100)),
                (
                    "s22_receipt",
                    models.JSONField(
                        blank=True,
                        help_text="JSON receipt returned by System 22 on successful ingest.",
                        null=True,
                    ),
                ),
                ("submitted_to_s22_at", models.DateTimeField(blank=True, null=True)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending — not yet submitted to System 22"),
                            ("submitted", "Submitted — awaiting System 22 confirmation"),
                            ("confirmed", "Confirmed — System 22 receipt received"),
                            ("failed", "Failed — submission error; requires manual retry"),
                        ],
                        db_index=True,
                        default="pending",
                        max_length=15,
                    ),
                ),
                ("retry_count", models.PositiveSmallIntegerField(default=0)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={
                "verbose_name": "Daily Commitment",
                "db_table": "audit_dailycommitment",
                "ordering": ["-date"],
                "indexes": [models.Index(fields=["date", "status"], name="audit_daily_date_status_idx")],
            },
        ),
        # ── ExportRequest ─────────────────────────────────────────────────────
        migrations.CreateModel(
            name="ExportRequest",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("actor_id", models.UUIDField(db_index=True, help_text="UserProfile.id of the requesting auditor.")),
                ("date_from", models.DateField()),
                ("date_to", models.DateField()),
                (
                    "institution_id",
                    models.UUIDField(
                        blank=True,
                        db_index=True,
                        help_text="Optional filter: limit export to a single institution.",
                        null=True,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending — queued for async processing"),
                            ("building", "Building — assembling export bundle"),
                            ("signed", "Signed — bundle ready for download"),
                            ("failed", "Failed — see error_detail"),
                        ],
                        db_index=True,
                        default="pending",
                        max_length=15,
                    ),
                ),
                (
                    "signed_bundle_url",
                    models.TextField(
                        blank=True,
                        default="",
                        help_text="Pre-signed MinIO URL for the ZIP bundle (TTL: EVS_EXPORT_URL_TTL_SECONDS).",
                    ),
                ),
                (
                    "bundle_hash",
                    models.CharField(
                        blank=True,
                        default="",
                        help_text="SHA-256 hex of the ZIP bundle.",
                        max_length=64,
                    ),
                ),
                (
                    "hsm_signature",
                    models.TextField(
                        blank=True,
                        default="",
                        help_text="Base64-encoded HSM signature over bundle_hash.",
                    ),
                ),
                ("hsm_key_id", models.CharField(blank=True, default="", max_length=100)),
                ("signed_at", models.DateTimeField(blank=True, null=True)),
                ("error_detail", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
            ],
            options={
                "verbose_name": "Export Request",
                "db_table": "audit_exportrequest",
                "ordering": ["-created_at"],
                "indexes": [
                    models.Index(fields=["actor_id", "created_at"], name="audit_export_actor_created_idx"),
                    models.Index(fields=["status", "created_at"], name="audit_export_status_created_idx"),
                ],
            },
        ),
        # ── RetentionTierLog ──────────────────────────────────────────────────
        migrations.CreateModel(
            name="RetentionTierLog",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                (
                    "tier_transition",
                    models.CharField(
                        choices=[
                            ("hot_warm", "Hot → Warm (90-day threshold)"),
                            ("warm_cold", "Warm → Cold (3-year threshold)"),
                        ],
                        db_index=True,
                        max_length=15,
                    ),
                ),
                ("run_date", models.DateField(db_index=True)),
                ("event_count", models.PositiveIntegerField(default=0)),
                (
                    "manifest_hash",
                    models.CharField(
                        blank=True,
                        default="",
                        help_text="SHA-256 of the migrated JSONL archive file.",
                        max_length=64,
                    ),
                ),
                ("hsm_signature", models.TextField(blank=True, default="")),
                ("hsm_key_id", models.CharField(blank=True, default="", max_length=100)),
                (
                    "archive_path",
                    models.CharField(
                        blank=True,
                        default="",
                        help_text="MinIO object key of the compressed JSONL archive.",
                        max_length=500,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("running", "Running"),
                            ("completed", "Completed"),
                            ("failed", "Failed"),
                        ],
                        db_index=True,
                        default="running",
                        max_length=15,
                    ),
                ),
                ("error_detail", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
            ],
            options={
                "verbose_name": "Retention Tier Log",
                "db_table": "audit_retentiontierlog",
                "ordering": ["-run_date"],
            },
        ),
        # ── GoLiveGate ────────────────────────────────────────────────────────
        migrations.CreateModel(
            name="GoLiveGate",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "gate_id",
                    models.SlugField(
                        db_index=True,
                        help_text="Machine-readable gate identifier, e.g. 'dr-failover-passed'.",
                        max_length=80,
                        unique=True,
                    ),
                ),
                ("title", models.CharField(max_length=200)),
                ("description", models.TextField(blank=True, default="")),
                (
                    "owner_role",
                    models.CharField(
                        blank=True,
                        default="",
                        help_text="IAM role name responsible for signing off this gate.",
                        max_length=80,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("open", "Open — not yet signed off"),
                            ("signed_off", "Signed Off"),
                        ],
                        db_index=True,
                        default="open",
                        max_length=15,
                    ),
                ),
                (
                    "signed_off_by",
                    models.UUIDField(
                        blank=True,
                        help_text="UserProfile.id of the sign-off authority.",
                        null=True,
                    ),
                ),
                ("signed_off_at", models.DateTimeField(blank=True, null=True)),
                (
                    "evidence",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        help_text="Structured evidence attached at sign-off (test results, report URLs, etc.).",
                    ),
                ),
                ("display_order", models.PositiveSmallIntegerField(default=0)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={
                "verbose_name": "Go-Live Gate",
                "db_table": "audit_golivegate",
                "ordering": ["display_order", "gate_id"],
            },
        ),
        # ── DRDrill ───────────────────────────────────────────────────────────
        migrations.CreateModel(
            name="DRDrill",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                (
                    "drill_type",
                    models.CharField(
                        choices=[
                            ("failover", "Database Failover"),
                            ("backup_restore", "Backup Restore"),
                            ("network_partition", "Network Partition"),
                        ],
                        db_index=True,
                        max_length=25,
                    ),
                ),
                ("started_at", models.DateTimeField(db_index=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "rto_seconds",
                    models.PositiveIntegerField(
                        blank=True,
                        help_text="Measured Recovery Time Objective in seconds (target ≤ 14 400).",
                        null=True,
                    ),
                ),
                (
                    "rpo_seconds",
                    models.PositiveIntegerField(
                        blank=True,
                        help_text="Measured Recovery Point Objective in seconds (target ≤ 3 600).",
                        null=True,
                    ),
                ),
                (
                    "passed",
                    models.BooleanField(
                        blank=True,
                        help_text="True if both RTO and RPO targets were met.",
                        null=True,
                    ),
                ),
                ("notes", models.TextField(blank=True, default="")),
                (
                    "triggered_by",
                    models.UUIDField(
                        blank=True,
                        help_text="UserProfile.id of the drill operator.",
                        null=True,
                    ),
                ),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={
                "verbose_name": "DR Drill",
                "db_table": "audit_drdrill",
                "ordering": ["-started_at"],
            },
        ),
    ]
