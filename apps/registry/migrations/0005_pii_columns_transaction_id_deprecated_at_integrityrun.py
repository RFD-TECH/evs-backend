"""Add typed PII columns to Credential, transaction_id to BatchIngest,
deprecated_at to CredentialSchemaVersion, and the IntegrityRun model.
"""

import uuid
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("registry", "0004_revocationrecord_source_signature_ref"),
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


    ]
