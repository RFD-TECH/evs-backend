import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0002_seed_permissions_and_roles"),
    ]

    operations = [
        migrations.CreateModel(
            name="UserRole",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("effective_from", models.DateField()),
                ("effective_to", models.DateField(blank=True, null=True)),
                ("granted_by", models.UUIDField(
                    blank=True, null=True,
                    help_text="keycloak_sub of the actor who granted this assignment.",
                )),
                ("justification", models.CharField(blank=True, max_length=500)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("revoke_reason", models.CharField(blank=True, max_length=500)),
                ("created_at", models.DateTimeField()),
                ("role", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="assignments",
                    to="users.role",
                )),
                ("user", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="role_assignments",
                    to="users.userprofile",
                )),
            ],
            options={
                "db_table": "users_userrole",
            },
        ),
        migrations.AddIndex(
            model_name="userrole",
            index=models.Index(fields=["user", "revoked_at"], name="userrole_user_active_idx"),
        ),
        migrations.CreateModel(
            name="RoleChangeEvent",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("change_type", models.CharField(
                    choices=[("assign", "Assign"), ("revoke", "Revoke")],
                    max_length=20,
                )),
                ("reason", models.CharField(blank=True, max_length=500)),
                ("occurred_at", models.DateTimeField()),
                ("role", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="change_events",
                    to="users.role",
                )),
                ("user", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="role_change_events",
                    to="users.userprofile",
                )),
            ],
            options={
                "db_table": "users_rolechangeevent",
                "ordering": ["-occurred_at"],
            },
        ),
        migrations.CreateModel(
            name="RoleMutualExclusion",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("role_a", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="exclusions_as_a",
                    to="users.role",
                )),
                ("role_b", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="exclusions_as_b",
                    to="users.role",
                )),
            ],
            options={
                "db_table": "users_rolemutualexclusion",
                "unique_together": {("role_a", "role_b")},
            },
        ),
    ]
