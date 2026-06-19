"""Phase 3 — RevocationRecord: add source enum and signature_ref."""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("registry", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="revocationrecord",
            name="source",
            field=models.CharField(
                choices=[
                    ("confirmed_fraud", "Confirmed Fraud"),
                    ("admin", "Administrative"),
                    ("dg", "Director-General Order"),
                ],
                default="admin",
                max_length=20,
                help_text="Authority under which the revocation was issued.",
            ),
        ),
        migrations.AddField(
            model_name="revocationrecord",
            name="signature_ref",
            field=models.CharField(
                blank=True, max_length=255,
                help_text="HSM signature token (kid:token) from the DG-sign step.",
            ),
        ),
    ]
