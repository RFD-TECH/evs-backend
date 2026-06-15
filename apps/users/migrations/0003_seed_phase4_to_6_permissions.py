"""Add Phase 4-6 permission codenames and update role grants.

New codenames:
  trust_anchor:manage  — Phase 4, TrustAnchor administration
  vault:read           — Phase 4, DocumentVaultObject browser
  connector:read       — Phase 5, read connector status
  connector:manage     — Phase 5, manage connector lifecycle
  queue:manage         — Phase 5, manual verification queue (Registrar)
  verification:waec    — Phase 5, submit WAEC verification
  foreign_credential:apply   — Phase 6, submit FCA application (Applicant)
  foreign_credential:read    — Phase 6, read FCA applications
  foreign_credential:triage  — Phase 6, triage + assign assessors (Registrar)
  foreign_credential:assess  — Phase 6, submit recommendations (Assessor)
  foreign_credential:sign    — Phase 6, DG digital signature

Updated matrix:
  system_administrator : ALL (including new codenames)
  registrar            : + vault:read, connector:read, queue:manage,
                           foreign_credential:read, foreign_credential:triage
  verification_officer : + verification:waec
  institution_officer  : + verification:waec
  candidate            : + foreign_credential:apply
  [new] assessor       : foreign_credential:read, foreign_credential:assess
  [new] director_general : foreign_credential:read, foreign_credential:sign
"""

import uuid

from django.db import migrations

NEW_PERMISSIONS = [
    ("trust_anchor:manage", "Add, revoke, and manage CA trust anchors."),
    ("vault:read",           "Browse and retrieve document vault objects."),
    ("connector:read",       "Read external connector status and health."),
    ("connector:manage",     "Manage connector lifecycle and credentials."),
    ("queue:manage",         "Claim and resolve manual verification queue items."),
    ("verification:waec",    "Submit WAEC verification requests."),
    ("foreign_credential:apply",  "Submit a foreign credential assessment application."),
    ("foreign_credential:read",   "Read foreign credential assessment applications."),
    ("foreign_credential:triage", "Triage applications and assign assessors."),
    ("foreign_credential:assess", "Submit equivalence recommendations."),
    ("foreign_credential:sign",   "DG digitally sign a foreign credential decision."),
]

NEW_ROLES = [
    ("assessor", "CLET Internal Assessor — reviews foreign credential applications.", True),
    ("director_general", "Director-General — signs foreign credential decisions.", True),
]

ADDITIONAL_GRANTS = {
    "system_administrator": [p[0] for p in NEW_PERMISSIONS],
    "registrar": [
        "vault:read", "connector:read", "queue:manage",
        "foreign_credential:read", "foreign_credential:triage",
    ],
    "verification_officer": ["verification:waec"],
    "institution_officer": ["verification:waec"],
    "candidate": ["foreign_credential:apply"],
    "assessor": ["foreign_credential:read", "foreign_credential:assess"],
    "director_general": ["foreign_credential:read", "foreign_credential:sign"],
}


def seed_forward(apps, schema_editor):
    Permission = apps.get_model("users", "Permission")
    Role = apps.get_model("users", "Role")
    RolePermission = apps.get_model("users", "RolePermission")

    perm_map = {}
    for codename, description in NEW_PERMISSIONS:
        p, _ = Permission.objects.get_or_create(
            codename=codename,
            defaults={"id": uuid.uuid4(), "description": description},
        )
        perm_map[codename] = p

    # All existing permissions for system_administrator
    all_perms = {p.codename: p for p in Permission.objects.all()}
    perm_map.update(all_perms)

    for name, description, is_internal in NEW_ROLES:
        Role.objects.get_or_create(
            name=name,
            defaults={
                "id": uuid.uuid4(),
                "description": description,
                "is_internal": is_internal,
                "is_active": True,
                "version": 1,
            },
        )

    for role_name, codenames in ADDITIONAL_GRANTS.items():
        try:
            role = Role.objects.get(name=role_name)
        except Role.DoesNotExist:
            continue
        for codename in codenames:
            perm = perm_map.get(codename)
            if perm is None:
                continue
            RolePermission.objects.get_or_create(
                role=role,
                permission=perm,
                defaults={"id": uuid.uuid4()},
            )
        role.version += 1
        role.save(update_fields=["version"])


def seed_reverse(apps, schema_editor):
    Permission = apps.get_model("users", "Permission")
    RolePermission = apps.get_model("users", "RolePermission")
    Role = apps.get_model("users", "Role")
    new_codenames = [p[0] for p in NEW_PERMISSIONS]
    RolePermission.objects.filter(permission__codename__in=new_codenames).delete()
    Permission.objects.filter(codename__in=new_codenames).delete()
    Role.objects.filter(name__in=[r[0] for r in NEW_ROLES]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0002_seed_permissions_and_roles"),
    ]

    operations = [
        migrations.RunPython(seed_forward, seed_reverse),
    ]
