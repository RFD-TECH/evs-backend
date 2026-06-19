"""Add typed PII columns to Credential, transaction_id to BatchIngest,
deprecated_at to CredentialSchemaVersion, and the IntegrityRun model.
"""

import uuid
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("registry", "0001_initial"),
    ]

    operations = [
        # ── CredentialSchemaVersion.deprecated_at ──────────────────────────────
        migrations.AddField(
            model_name="credentialschemaversion",
            name="deprecated_at",
            field=models.DateTimeField(
                blank=True, null=True,
                help_text="When this schema version was deprecated; NULL = still current.",
            ),
        ),

        # ── BatchIngest.transaction_id ─────────────────────────────────────────
        migrations.AddField(
            model_name="batchingest",
            name="transaction_id",
            field=models.UUIDField(
                default=uuid.uuid4,
                unique=True,
                db_index=True,
                help_text="Externally-visible idempotency key for this batch transaction.",
            ),
        ),

        # ── Credential typed PII columns ───────────────────────────────────────
        migrations.AddField(
            model_name="credential",
            name="student_full_name",
            field=models.CharField(blank=True, db_index=True, max_length=300),
        ),
        migrations.AddField(
            model_name="credential",
            name="date_of_birth",
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="credential",
            name="waec_index",
            field=models.CharField(blank=True, db_index=True, max_length=50),
        ),
        migrations.AddField(
            model_name="credential",
            name="llb_award_date",
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="credential",
            name="institution_code",
            field=models.CharField(blank=True, db_index=True, max_length=20),
        ),
        migrations.AddField(
            model_name="credential",
            name="graduate_index_number",
            field=models.CharField(blank=True, db_index=True, max_length=100),
        ),
        migrations.AddField(
            model_name="credential",
            name="degree_classification",
            field=models.CharField(blank=True, max_length=50),
        ),
        migrations.AddField(
            model_name="credential",
            name="programme_code",
            field=models.CharField(blank=True, db_index=True, max_length=50),
        ),
        migrations.AddIndex(
            model_name="credential",
            index=models.Index(fields=["graduate_index_number"], name="cred_grad_idx_num_idx"),
        ),

        # ── IntegrityRun model ─────────────────────────────────────────────────
        migrations.CreateModel(
            name="IntegrityRun",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("started_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("records_checked", models.PositiveIntegerField(default=0)),
                ("tampered_count", models.PositiveIntegerField(default=0)),
                ("tampered_ids", models.JSONField(default=list,
                    help_text="UUIDs of credentials found tampered (capped at 100 for storage).")),
                ("anchor_hash", models.CharField(blank=True, max_length=64,
                    help_text="chain_hash of the AuditEvent written for this sweep.")),
                ("status", models.CharField(default="running", max_length=20)),
            ],
            options={
                "db_table": "registry_integrityrun",
                "ordering": ["-started_at"],
            },
        ),
    ]
