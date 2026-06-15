"""Phase 8 — Legacy Migration initial migration (EVS-F09)."""
import uuid

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("registry", "0002_credential_legacy_fields"),
    ]

    operations = [
        # MigrationWave
        migrations.CreateModel(
            name="MigrationWave",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ("name", models.CharField(max_length=255, unique=True)),
                ("description", models.TextField(blank=True)),
                ("status", models.CharField(
                    choices=[
                        ("planned", "Planned"),
                        ("active", "Active — ingesting"),
                        ("live", "Live — fully confirmed and published"),
                        ("rolled_back", "Rolled Back"),
                        ("quarantined", "Quarantined — compliance hold"),
                    ],
                    db_index=True, default="planned", max_length=15,
                )),
                ("institution_id", models.UUIDField(db_index=True)),
                ("graduation_year_from", models.PositiveSmallIntegerField(blank=True, null=True)),
                ("graduation_year_to", models.PositiveSmallIntegerField(blank=True, null=True)),
                ("confirmation_deadline", models.DateTimeField()),
                ("activated_at", models.DateTimeField(blank=True, null=True)),
                ("activated_by", models.UUIDField(blank=True, null=True)),
                ("went_live_at", models.DateTimeField(blank=True, null=True)),
                ("went_live_by", models.UUIDField(blank=True, null=True)),
                ("rolled_back_at", models.DateTimeField(blank=True, null=True)),
                ("rolled_back_by", models.UUIDField(blank=True, null=True)),
                ("rollback_reason", models.TextField(blank=True)),
                ("quarantined_at", models.DateTimeField(blank=True, null=True)),
                ("quarantine_reason", models.TextField(blank=True)),
                ("created_by", models.UUIDField(blank=True, null=True)),
                ("created_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"db_table": "legacy_migrationwave", "ordering": ["-created_at"]},
        ),

        # LegacyBatch
        migrations.CreateModel(
            name="LegacyBatch",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ("wave", models.ForeignKey(
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="batches", to="legacy_migration.migrationwave",
                )),
                ("batch_ref", models.CharField(max_length=100, unique=True)),
                ("uploaded_by", models.UUIDField()),
                ("file_name", models.CharField(max_length=500)),
                ("file_sha256", models.CharField(max_length=64)),
                ("record_count", models.PositiveIntegerField(default=0)),
                ("ingested_count", models.PositiveIntegerField(default=0)),
                ("confirmed_count", models.PositiveIntegerField(default=0)),
                ("rejected_count", models.PositiveIntegerField(default=0)),
                ("status", models.CharField(
                    choices=[
                        ("pending", "Pending"),
                        ("processing", "Processing"),
                        ("awaiting_confirmation", "Awaiting Institution Confirmation"),
                        ("confirmed", "Confirmed"),
                        ("rejected", "Rejected"),
                    ],
                    db_index=True, default="pending", max_length=25,
                )),
                ("affidavit_ref", models.CharField(blank=True, max_length=255)),
                ("affidavit_verified", models.BooleanField(default=False)),
                ("error_summary", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"db_table": "legacy_legacybatch", "ordering": ["-created_at"]},
        ),

        # LegacyConfirmation
        migrations.CreateModel(
            name="LegacyConfirmation",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ("batch", models.ForeignKey(
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="confirmations", to="legacy_migration.legacybatch",
                )),
                ("credential_id", models.UUIDField(db_index=True)),
                ("decision", models.CharField(
                    choices=[("confirmed", "Confirmed"), ("rejected", "Rejected")],
                    db_index=True, max_length=10,
                )),
                ("decided_by", models.UUIDField()),
                ("decided_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("rejection_reason", models.TextField(blank=True)),
                ("audit_hash", models.CharField(blank=True, max_length=64)),
            ],
            options={"db_table": "legacy_legacyconfirmation", "ordering": ["-decided_at"]},
        ),
        migrations.AddConstraint(
            model_name="LegacyConfirmation",
            constraint=models.UniqueConstraint(
                fields=["batch", "credential_id"], name="legacy_confirmation_unique"
            ),
        ),

        # CredentialVersion
        migrations.CreateModel(
            name="CredentialVersion",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ("credential_id", models.UUIDField(db_index=True)),
                ("version", models.PositiveIntegerField()),
                ("payload_snapshot", models.JSONField()),
                ("sha256_at_version", models.CharField(max_length=64)),
                ("changed_by", models.UUIDField(blank=True, null=True)),
                ("change_reason", models.CharField(blank=True, max_length=500)),
                ("created_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
            ],
            options={"db_table": "legacy_credentialversion", "ordering": ["credential_id", "version"]},
        ),
        migrations.AddConstraint(
            model_name="CredentialVersion",
            constraint=models.UniqueConstraint(
                fields=["credential_id", "version"], name="legacy_credver_unique"
            ),
        ),

        # MigrationAuditReport
        migrations.CreateModel(
            name="MigrationAuditReport",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ("wave", models.OneToOneField(
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="audit_report", to="legacy_migration.migrationwave",
                )),
                ("status", models.CharField(
                    choices=[
                        ("draft", "Draft"),
                        ("admin_signed", "Admin Signed — awaiting Registrar"),
                        ("fully_signed", "Fully Signed — ready for go-live"),
                    ],
                    db_index=True, default="draft", max_length=15,
                )),
                ("report_payload", models.JSONField(default=dict)),
                ("admin_signer_id", models.UUIDField(blank=True, null=True)),
                ("admin_signed_at", models.DateTimeField(blank=True, null=True)),
                ("admin_signature_hash", models.CharField(blank=True, max_length=64)),
                ("registrar_signer_id", models.UUIDField(blank=True, null=True)),
                ("registrar_signed_at", models.DateTimeField(blank=True, null=True)),
                ("registrar_signature_hash", models.CharField(blank=True, max_length=64)),
                ("audit_chain_ref", models.CharField(blank=True, max_length=100)),
                ("generated_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("generated_by", models.UUIDField(blank=True, null=True)),
            ],
            options={"db_table": "legacy_migrationauditreport", "ordering": ["-generated_at"]},
        ),
    ]
