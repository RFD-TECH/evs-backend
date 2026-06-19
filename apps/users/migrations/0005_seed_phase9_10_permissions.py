"""Phase 9 & 10 — Seed cryptographic assurance and go-live permissions and roles."""
from django.db import migrations

PHASE9_PERMISSIONS = [
    ("audit:integrity",    "View integrity run results and Merkle roots"),
    ("audit:export",       "Submit and download Auditor-General signed export bundles"),
    ("dg:export:sign",     "HSM-sign export bundles (step-up MFA required)"),
]

PHASE10_PERMISSIONS = [
    ("ops:go_live",        "Sign off go-live gates and manage cutover runbook"),
    ("ops:dr_drill",       "Schedule, record, and view DR drill results"),
]

# New role: auditor_general
AUDITOR_GENERAL_PERMS = ["audit:export", "dg:export:sign", "audit:integrity"]

# Additional grants to existing roles
ROLE_GRANTS = {
    "system_administrator": [
        "audit:integrity", "audit:export", "dg:export:sign",
        "ops:go_live", "ops:dr_drill",
    ],
    "registrar": [
        "audit:integrity", "ops:go_live",
    ],
    "programme_manager": [
        "ops:go_live", "ops:dr_drill",
    ],
}


def seed_forward(apps, schema_editor):
    Permission = apps.get_model("users", "Permission")
    Role = apps.get_model("users", "Role")
    RolePermission = apps.get_model("users", "RolePermission")

    all_perms = PHASE9_PERMISSIONS + PHASE10_PERMISSIONS
    perm_map = {}
    for codename, description in all_perms:
        perm, _ = Permission.objects.get_or_create(
            codename=codename, defaults={"description": description}
        )
        perm_map[codename] = perm

    # Create auditor_general role
    ag_role, _ = Role.objects.get_or_create(
        name="auditor_general",
        defaults={"description": "Auditor-General representative — exports and cryptographic sign-off."},
    )
    for codename in AUDITOR_GENERAL_PERMS:
        RolePermission.objects.get_or_create(role=ag_role, permission=perm_map[codename])

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
    codenames = [c for c, _ in PHASE9_PERMISSIONS + PHASE10_PERMISSIONS]
    Permission.objects.filter(codename__in=codenames).delete()

    Role = apps.get_model("users", "Role")
    Role.objects.filter(name="auditor_general").delete()


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0004_seed_phase7_8_permissions"),
    ]

    operations = [
        migrations.RunPython(seed_forward, seed_reverse),
    ]
