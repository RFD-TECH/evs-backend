"""Phase 7 — Fraud Detection initial migration (EVS-F05)."""
import uuid

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("registry", "0001_initial"),
    ]

    operations = [
        # RuleDefinition
        migrations.CreateModel(
            name="RuleDefinition",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ("name", models.CharField(max_length=255)),
                ("description", models.TextField(blank=True)),
                ("severity_default", models.CharField(
                    choices=[("low", "Low"), ("medium", "Medium"), ("high", "High")],
                    default="medium", max_length=10,
                )),
                ("predicate_json", models.JSONField(
                    help_text="JSON predicate tree evaluated against each credential payload.")),
                ("evidence_template", models.TextField(blank=True)),
                ("version", models.PositiveIntegerField(default=1)),
                ("enabled", models.BooleanField(db_index=True, default=False)),
                ("created_by", models.UUIDField(blank=True, null=True)),
                ("approved_by", models.UUIDField(blank=True, null=True)),
                ("second_approver", models.UUIDField(blank=True, null=True)),
                ("effective_from", models.DateTimeField(blank=True, db_index=True, null=True)),
                ("deprecated_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"db_table": "fraud_ruledefinition", "ordering": ["name", "-version"]},
        ),

        # RuleRun
        migrations.CreateModel(
            name="RuleRun",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ("trigger", models.CharField(
                    choices=[
                        ("post_ingest", "Post-Ingest"),
                        ("nightly", "Nightly Full Sweep"),
                        ("on_demand", "On-Demand"),
                    ],
                    db_index=True, max_length=15,
                )),
                ("triggered_by", models.UUIDField(blank=True, null=True)),
                ("batch_id", models.UUIDField(blank=True, db_index=True, null=True)),
                ("run_started_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("run_finished_at", models.DateTimeField(blank=True, null=True)),
                ("records_scanned", models.PositiveIntegerField(default=0)),
                ("rules_evaluated", models.PositiveIntegerField(default=0)),
                ("flags_created", models.PositiveIntegerField(default=0)),
                ("status", models.CharField(
                    choices=[("running", "Running"), ("completed", "Completed"), ("failed", "Failed")],
                    db_index=True, default="running", max_length=15,
                )),
                ("error_message", models.TextField(blank=True)),
            ],
            options={"db_table": "fraud_rulerun", "ordering": ["-run_started_at"]},
        ),

        # FraudFlag
        migrations.CreateModel(
            name="FraudFlag",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ("flag_type", models.CharField(
                    choices=[
                        ("duplicate_credential", "Duplicate Credential Usage"),
                        ("duplicate_index", "Duplicate Graduate Index (Exact)"),
                        ("fuzzy_identity", "Fuzzy Identity Match"),
                        ("rule_match", "Metadata Anomaly Rule"),
                    ],
                    db_index=True, max_length=25,
                )),
                ("credential_ids", models.JSONField(default=list)),
                ("applicant_ids", models.JSONField(default=list)),
                ("rule", models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.PROTECT,
                    related_name="flags", to="fraud_detection.ruledefinition",
                )),
                ("run", models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name="flags", to="fraud_detection.rulerun",
                )),
                ("severity", models.CharField(
                    choices=[("low", "Low"), ("medium", "Medium"), ("high", "High")],
                    db_index=True, max_length=10,
                )),
                ("status", models.CharField(
                    choices=[
                        ("new", "New"),
                        ("under_investigation", "Under Investigation"),
                        ("confirmed_fraud", "Confirmed Fraud"),
                        ("false_positive", "False Positive"),
                    ],
                    db_index=True, default="new", max_length=25,
                )),
                ("evidence_payload", models.JSONField(default=dict)),
                ("evidence_bundle_uri", models.CharField(blank=True, max_length=500)),
                ("fuzzy_similarity_score", models.FloatField(blank=True, null=True)),
                ("resolution_justification", models.TextField(blank=True)),
                ("resolver_id", models.UUIDField(blank=True, null=True)),
                ("resolved_at", models.DateTimeField(blank=True, null=True)),
                ("audit_hash", models.CharField(blank=True, max_length=64)),
                ("escalated_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"db_table": "fraud_fraudflag", "ordering": ["-created_at"]},
        ),
        migrations.AddIndex(
            model_name="FraudFlag",
            index=models.Index(fields=["severity", "status", "created_at"], name="fraud_flag_sev_status_idx"),
        ),
        migrations.AddIndex(
            model_name="FraudFlag",
            index=models.Index(fields=["status", "escalated_at"], name="fraud_flag_status_esc_idx"),
        ),
        migrations.AddIndex(
            model_name="FraudFlag",
            index=models.Index(fields=["flag_type", "status"], name="fraud_flag_type_status_idx"),
        ),

        # WatchlistEntry
        migrations.CreateModel(
            name="WatchlistEntry",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ("applicant_id", models.UUIDField(db_index=True)),
                ("reason_flag", models.ForeignKey(
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="watchlist_entries", to="fraud_detection.fraudflag",
                )),
                ("added_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("added_by", models.UUIDField()),
                ("status", models.CharField(
                    choices=[("active", "Active"), ("cleared", "Cleared")],
                    db_index=True, default="active", max_length=10,
                )),
                ("cleared_at", models.DateTimeField(blank=True, null=True)),
                ("cleared_reason", models.TextField(blank=True)),
            ],
            options={"db_table": "fraud_watchlistentry", "ordering": ["-added_at"]},
        ),
        migrations.AddIndex(
            model_name="WatchlistEntry",
            index=models.Index(fields=["applicant_id", "status"], name="fraud_watchlist_appl_idx"),
        ),

        # FlagAction
        migrations.CreateModel(
            name="FlagAction",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ("flag", models.ForeignKey(
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="actions", to="fraud_detection.fraudflag",
                )),
                ("actor_user_id", models.UUIDField(blank=True, null=True)),
                ("action", models.CharField(
                    choices=[
                        ("created", "Created"),
                        ("viewed", "Viewed"),
                        ("escalated", "Escalated"),
                        ("status_change", "Status Change"),
                        ("resolved", "Resolved"),
                        ("addendum", "Addendum Added"),
                    ],
                    db_index=True, max_length=20,
                )),
                ("occurred_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("payload", models.JSONField(default=dict)),
                ("audit_chain_ref", models.CharField(blank=True, max_length=100)),
            ],
            options={"db_table": "fraud_flagaction", "ordering": ["occurred_at"]},
        ),
    ]
