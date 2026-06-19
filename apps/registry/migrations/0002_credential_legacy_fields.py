"""Phase 8 — Add legacy flag, wave_id, STATUS_SUSPENDED to Credential (EVS-F09)."""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("registry", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="Credential",
            name="legacy",
            field=models.BooleanField(
                db_index=True,
                default=False,
                help_text="True if this credential was migrated from a legacy system.",
            ),
        ),
        migrations.AddField(
            model_name="Credential",
            name="wave_id",
            field=models.UUIDField(
                blank=True,
                db_index=True,
                null=True,
                help_text="MigrationWave.id — set only for legacy credentials.",
            ),
        ),
        # schema_version becomes nullable to allow legacy records without a schema
        migrations.AlterField(
            model_name="Credential",
            name="schema_version",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=models.PROTECT,
                related_name="credentials",
                to="registry.credentialschemaversion",
                help_text="Null for legacy-migrated credentials that predate the schema registry.",
            ),
        ),
        # Add STATUS_SUSPENDED to the choices (DB-level; Django enforces via choices at form layer)
        migrations.AlterField(
            model_name="Credential",
            name="status",
            field=models.CharField(
                choices=[
                    ("active", "Active"),
                    ("revoked", "Revoked"),
                    ("quarantined", "Quarantined — under review"),
                    ("suspended", "Suspended — migration rollback or hold"),
                ],
                db_index=True,
                default="active",
                max_length=15,
            ),
        ),
    ]
