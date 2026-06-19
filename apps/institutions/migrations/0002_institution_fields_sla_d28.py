"""Add missing InstitutionMaster fields, rename sla_d7_notified → sla_d28_notified,
and update SlaEvent d7_reminder → d28_reminder.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("institutions", "0001_initial"),
    ]

    operations = [
        # ── InstitutionMaster missing fields ───────────────────────────────────
        migrations.AddField(
            model_name="institutionmaster",
            name="country_code",
            field=models.CharField(
                db_index=True, default="GH", max_length=3,
                help_text="ISO 3166-1 alpha-3 country code.",
            ),
        ),
        migrations.AddField(
            model_name="institutionmaster",
            name="programmes",
            field=models.JSONField(
                default=list,
                help_text="List of programme descriptors offered by the institution.",
            ),
        ),
        migrations.AddField(
            model_name="institutionmaster",
            name="contact_officers",
            field=models.JSONField(
                default=list,
                help_text="List of {name, email, phone} for institution liaison officers.",
            ),
        ),
        migrations.AddField(
            model_name="institutionmaster",
            name="api_keys",
            field=models.JSONField(
                default=dict,
                help_text="Hashed API key metadata for M2M access (never store plain keys).",
            ),
        ),

        # ── GraduationCycle: rename sla_d7_notified → sla_d28_notified ────────
        migrations.RenameField(
            model_name="graduationcycle",
            old_name="sla_d7_notified",
            new_name="sla_d28_notified",
        ),
        migrations.AlterField(
            model_name="graduationcycle",
            name="sla_d28_notified",
            field=models.BooleanField(
                default=False,
                help_text="True once the D-28 (28 days remaining) statutory reminder has been sent.",
            ),
        ),

        # ── SlaEvent: data migration d7_reminder → d28_reminder ───────────────
        migrations.RunSQL(
            sql="UPDATE institutions_slaevent SET event_type = 'd28_reminder' WHERE event_type = 'd7_reminder';",
            reverse_sql="UPDATE institutions_slaevent SET event_type = 'd7_reminder' WHERE event_type = 'd28_reminder';",
        ),
        migrations.AlterField(
            model_name="slaevent",
            name="event_type",
            field=models.CharField(
                choices=[
                    ("d20_reminder", "D-20 Reminder Sent"),
                    ("d28_reminder", "D-28 Statutory Reminder Sent"),
                    ("overdue_escalation", "Overdue Escalation"),
                    ("submission_received", "Submission Received"),
                ],
                db_index=True,
                max_length=30,
            ),
        ),
    ]
