"""Seed Permission catalog and Role whitelist, then wire the initial matrix.

Permissions are code-owned and never created at runtime. This migration is the
single source of truth for what codenames exist in EVS.

Roles mirror the Keycloak client-roles on evs-api. Role assignments live in
IAM; EVS only stores this whitelist so it can anchor the RolePermission FK.

Permission matrix (role → codenames):

  system_administrator : ALL
  registrar            : institution:read, institution:manage, user:read,
                         credential:read, credential:read_full, credential:revoke,
                         audit:read
  verification_officer : credential:read, audit:read
  institution_officer  : institution:read, bulk:ingest, credential:read
  candidate            : credential:read
"""

import uuid

from django.db import migrations

# ── Catalog ────────────────────────────────────────────────────────────────────

PERMISSIONS = [
    ("user:read",           "Read user profile list and individual profiles."),
    ("institution:read",    "Read institution master records and graduation cycles."),
    ("institution:manage",  "Create, update, and link institutions. Approve cycles."),
    ("role:manage",         "Modify the EVS permission matrix (add/remove grants)."),
    ("credential:read",     "Read credential records and verification status."),
    ("credential:read_full","Read full PII credential data (restricted to registrar / admin)."),
    ("credential:revoke",   "Revoke a credential and issue a RevocationRecord."),
    ("bulk:ingest",         "Upload a graduation-cycle batch for processing."),
    ("audit:read",          "Read AuditEvent and SecurityEvent logs."),
]

ROLES = [
    ("system_administrator", "CLET system administrator — full access.", True),
    ("registrar",            "CLET registrar — manages institutions and registry.", True),
    ("verification_officer", "CLET verification officer — reads and queries credentials.", True),
    ("institution_officer",  "University / polytechnic officer — submits batch uploads.", False),
    ("candidate",            "Graduating candidate — reads own credential.", False),
]

# role_name → list of codenames that role is granted
INITIAL_MATRIX = {
    "system_administrator": [p[0] for p in PERMISSIONS],  # wildcard via DB
    "registrar": [
        "institution:read", "institution:manage", "user:read",
        "credential:read", "credential:read_full", "credential:revoke",
        "audit:read",
    ],
    "verification_officer": ["credential:read", "audit:read"],
    "institution_officer":  ["institution:read", "bulk:ingest", "credential:read"],
    "candidate":            ["credential:read"],
}


def seed_forward(apps, schema_editor):
    Permission = apps.get_model("users", "Permission")
    Role = apps.get_model("users", "Role")
    RolePermission = apps.get_model("users", "RolePermission")

    perm_map = {}
    for codename, description in PERMISSIONS:
        p, _ = Permission.objects.get_or_create(
            codename=codename,
            defaults={"id": uuid.uuid4(), "description": description},
        )
        perm_map[codename] = p

    role_map = {}
    for name, description, is_internal in ROLES:
        r, _ = Role.objects.get_or_create(
            name=name,
            defaults={
                "id": uuid.uuid4(),
                "description": description,
                "is_internal": is_internal,
                "is_active": True,
                "version": 1,
            },
        )
        role_map[name] = r

    for role_name, codenames in INITIAL_MATRIX.items():
        role = role_map[role_name]
        for codename in codenames:
            perm = perm_map[codename]
            RolePermission.objects.get_or_create(
                role=role,
                permission=perm,
                defaults={"id": uuid.uuid4()},
            )


def seed_reverse(apps, schema_editor):
    RolePermission = apps.get_model("users", "RolePermission")
    Role = apps.get_model("users", "Role")
    Permission = apps.get_model("users", "Permission")
    RolePermission.objects.filter(role__name__in=[r[0] for r in ROLES]).delete()
    Role.objects.filter(name__in=[r[0] for r in ROLES]).delete()
    Permission.objects.filter(codename__in=[p[0] for p in PERMISSIONS]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(seed_forward, seed_reverse),
    ]
