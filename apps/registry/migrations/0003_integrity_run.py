# Generated migration for Phase 9 registry model — IntegrityRun.
import django.utils.timezone
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("registry", "0002_credential_legacy_fields"),
    ]

    operations = [
        migrations.CreateModel(
            name="IntegrityRun",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                (
                    "sweep_type",
                    models.CharField(
                        choices=[
                            ("scheduled", "Scheduled — triggered by Celery beat"),
                            ("manual", "Manual — triggered via API"),
                        ],
                        db_index=True,
                        default="scheduled",
                        max_length=12,
                    ),
                ),
                ("started_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("total_checked", models.PositiveIntegerField(default=0)),
                ("tampered_count", models.PositiveIntegerField(default=0)),
                (
                    "merkle_root",
                    models.CharField(
                        blank=True,
                        default="",
                        help_text="SHA-256 of all '{uuid}:{sha256}' pairs sorted by credential UUID.",
                        max_length=64,
                    ),
                ),
                (
                    "hsm_signature",
                    models.TextField(
                        blank=True,
                        default="",
                        help_text="Base64-encoded HSM signature over merkle_root.",
                    ),
                ),
                ("hsm_key_id", models.CharField(blank=True, default="", max_length=100)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("running", "Running — sweep in progress"),
                            ("completed", "Completed — all credentials checked"),
                            ("partial", "Partial — sweep interrupted; checkpoint saved"),
                            ("failed", "Failed — unrecoverable error"),
                        ],
                        db_index=True,
                        default="running",
                        max_length=12,
                    ),
                ),
                (
                    "checkpoint_state",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        help_text="Crash-recovery state — stores {'last_id': '<uuid>', 'checked': N, 'tampered': N}.",
                    ),
                ),
                (
                    "triggered_by",
                    models.UUIDField(
                        blank=True,
                        help_text="UserProfile.id — set for manual runs only.",
                        null=True,
                    ),
                ),
                ("error_detail", models.TextField(blank=True, default="")),
            ],
            options={
                "verbose_name": "Integrity Run",
                "db_table": "registry_integrityrun",
                "ordering": ["-started_at"],
                "indexes": [
                    models.Index(fields=["status", "started_at"], name="registry_integrun_status_idx"),
                    models.Index(fields=["sweep_type", "started_at"], name="registry_integrun_type_idx"),
                ],
            },
        ),
    ]
