"""Phase 3 — VerificationSession schema update.

Changes vs 0001_initial:
  - PK changed from UUIDField to BigAutoField (BIGSERIAL).
  - result_id UUIDField added (unique, indexed) — external stable identifier.
  - channel CharField added (qr_scan | api).
  - device_fingerprint CharField added.
  - payload_hash CharField added (SHA-256 of raw JWT token).
  - checks_performed JSONField added.
  - audit_chain_ref CharField added.
  - verification_ms renamed → latency_ms.
"""
import uuid

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("verification", "0001_initial"),
    ]

    operations = [
        # 1. Add result_id first (before dropping old UUID PK)
        migrations.AddField(
            model_name="verificationsession",
            name="result_id",
            field=models.UUIDField(
                null=True, editable=False,
                help_text="Stable external identifier — used in GET /v1/verify/results/{result_id}.",
            ),
        ),
        migrations.AlterUniqueTogether(
            name="verificationsession",
            unique_together=set(),
        ),
        # 2. Backfill result_id from existing id values
        migrations.RunSQL(
            "UPDATE verification_verificationsession SET result_id = id WHERE result_id IS NULL;",
            reverse_sql=migrations.RunSQL.noop,
        ),
        # 3. Make result_id non-null, unique, indexed
        migrations.AlterField(
            model_name="verificationsession",
            name="result_id",
            field=models.UUIDField(
                default=uuid.uuid4, editable=False, unique=True, db_index=True,
                help_text="Stable external identifier — used in GET /v1/verify/results/{result_id}.",
            ),
        ),
        # 4. Swap PK: drop UUID PK, add BIGSERIAL PK
        migrations.RunSQL(
            sql="""
                ALTER TABLE verification_verificationsession
                    DROP CONSTRAINT verification_verificationsession_pkey;
                ALTER TABLE verification_verificationsession
                    DROP COLUMN id;
                ALTER TABLE verification_verificationsession
                    ADD COLUMN id BIGSERIAL PRIMARY KEY;
            """,
            reverse_sql="""
                ALTER TABLE verification_verificationsession DROP COLUMN id;
                ALTER TABLE verification_verificationsession
                    ADD COLUMN id uuid DEFAULT gen_random_uuid() PRIMARY KEY;
            """,
        ),
        migrations.AlterField(
            model_name="verificationsession",
            name="id",
            field=models.BigAutoField(primary_key=True, serialize=False),
        ),
        # 5. Rename verification_ms → latency_ms
        migrations.RenameField(
            model_name="verificationsession",
            old_name="verification_ms",
            new_name="latency_ms",
        ),
        # 6. Add remaining new fields
        migrations.AddField(
            model_name="verificationsession",
            name="channel",
            field=models.CharField(
                choices=[("qr_scan", "QR Scan"), ("api", "API")],
                default="qr_scan", max_length=30,
                help_text="Scan channel: qr_scan (camera) or api (programmatic).",
            ),
        ),
        migrations.AddField(
            model_name="verificationsession",
            name="device_fingerprint",
            field=models.CharField(
                blank=True, max_length=255,
                help_text="Client-supplied device fingerprint for fraud correlation.",
            ),
        ),
        migrations.AddField(
            model_name="verificationsession",
            name="payload_hash",
            field=models.CharField(
                blank=True, max_length=64,
                help_text="SHA-256 hex of the raw JWT token string.",
            ),
        ),
        migrations.AddField(
            model_name="verificationsession",
            name="checks_performed",
            field=models.JSONField(
                default=list,
                help_text="Ordered list of check names that ran before the result was reached.",
            ),
        ),
        migrations.AddField(
            model_name="verificationsession",
            name="audit_chain_ref",
            field=models.CharField(
                blank=True, max_length=64,
                help_text="chain_hash of the AuditEvent written for this session (async-filled).",
            ),
        ),
    ]
