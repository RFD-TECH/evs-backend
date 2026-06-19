"""Phase 7 & 8 — Seed fraud detection + legacy migration permissions and roles."""
from django.db import migrations

PHASE7_PERMISSIONS = [
    ("fraud:read",         "View fraud flags, rules, runs, and watchlist"),
    ("fraud:investigate",  "Investigate, resolve, and add addenda to fraud flags"),
    ("fraud:manage_rules", "Create, approve, activate, and deprecate detection rules"),
    ("fraud:run",          "Trigger on-demand fraud detection runs"),
    ("watchlist:read",     "View the applicant watchlist"),
]

PHASE8_PERMISSIONS = [
    ("legacy:ingest",        "Upload and initiate a legacy credential batch"),
    ("legacy:confirm",       "Confirm or reject individual legacy batch records"),
    ("legacy:manage",        "Manage migration waves: activate, rollback, quarantine"),
    ("legacy:audit_report",  "Generate and sign the pre-go-live dual-authority audit report"),
]

PROGRAMME_MANAGER_PERMS = ["legacy:manage", "legacy:audit_report", "legacy:ingest"]

# Updates to existing role grants
ROLE_GRANTS = {
    "system_administrator": [
        "fraud:read", "fraud:investigate", "fraud:manage_rules", "fraud:run", "watchlist:read",
        "legacy:ingest", "legacy:confirm", "legacy:manage", "legacy:audit_report",
    ],
    "registrar": [
        "fraud:read", "fraud:investigate", "fraud:run",
        "legacy:audit_report", "legacy:manage",
    ],
    "verification_officer": [
        "fraud:read", "watchlist:read",
    ],
    "institution_officer": [
        "legacy:ingest", "legacy:confirm",
    ],
}


def seed_forward(apps, schema_editor):
    Permission = apps.get_model("users", "Permission")
    Role = apps.get_model("users", "Role")
    RolePermission = apps.get_model("users", "RolePermission")

    # Create permissions
    all_perms = PHASE7_PERMISSIONS + PHASE8_PERMISSIONS
    perm_map = {}
    for codename, description in all_perms:
        perm, _ = Permission.objects.get_or_create(
            codename=codename, defaults={"description": description}
        )
        perm_map[codename] = perm

    # Create programme_manager role
    pm_role, _ = Role.objects.get_or_create(
        name="programme_manager",
        defaults={"description": "Manages legacy credential migration waves and audit reports."},
    )
    for codename in PROGRAMME_MANAGER_PERMS:
        RolePermission.objects.get_or_create(role=pm_role, permission=perm_map[codename])

    # Grant to existing roles
    for role_name, codenames in ROLE_GRANTS.items():
        try:
            role = Role.objects.get(name=role_name)
        except Role.DoesNotExist:
            continue
        for codename in codenames:
            perm = perm_map.get(codename)
            if perm:
                RolePermission.objects.get_or_create(role=role, permission=perm)


def seed_reverse(apps, schema_editor):
    Permission = apps.get_model("users", "Permission")
    codenames = [c for c, _ in PHASE7_PERMISSIONS + PHASE8_PERMISSIONS]
    Permission.objects.filter(codename__in=codenames).delete()

    Role = apps.get_model("users", "Role")
    Role.objects.filter(name="programme_manager").delete()


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0003_seed_phase4_to_6_permissions"),
        ("fraud_detection", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(seed_forward, seed_reverse),
    ]
