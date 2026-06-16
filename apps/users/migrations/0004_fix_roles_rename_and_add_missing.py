"""Fix role catalog to match SRS §3.2 and Keycloak client-role names.

Changes from 0002:
  * Rename verification_officer → verifier (Keycloak role name in SRS).
  * Add 4 missing roles: internal_assessor, gtec_assessor, director_general, auditor.
  * Wire initial permission matrix for the new roles.
"""

import uuid

from django.db import migrations

NEW_ROLES = [
    (
        "verifier",
        "CLET verifier — reads credentials and queries via QR/portal.",
        True,
        ["credential:read", "audit:read"],
    ),
    (
        "internal_assessor",
        "CLET internal assessor — reviews full credential data for accuracy.",
        True,
        ["credential:read", "credential:read_full"],
    ),
    (
        "gtec_assessor",
        "GTEC external assessor — reviews credential data on behalf of GTEC.",
        True,
        ["credential:read", "credential:read_full"],
    ),
    (
        "director_general",
        "CLET Director General — approves revocations and has oversight of the registry.",
        True,
        ["credential:read", "credential:read_full", "credential:revoke", "audit:read", "institution:read"],
    ),
    (
        "auditor",
        "Independent auditor — read-only access to audit trail.",
        True,
        ["audit:read", "credential:read"],
    ),
]


def forward(apps, schema_editor):
    Role = apps.get_model("users", "Role")
    Permission = apps.get_model("users", "Permission")
    RolePermission = apps.get_model("users", "RolePermission")

    # Rename verification_officer → verifier (Keycloak canonical name per SRS)
    old_role = Role.objects.filter(name="verification_officer").first()
    if old_role:
        old_role.name = "verifier"
        old_role.description = "CLET verifier — reads credentials and queries via QR/portal."
        old_role.save()

    perm_cache = {p.codename: p for p in Permission.objects.all()}

    for name, description, is_internal, codenames in NEW_ROLES:
        # Skip verifier — it was renamed above (already exists)
        if name == "verifier":
            role = Role.objects.filter(name="verifier").first()
            if role is None:
                continue
            # Ensure the new permission set is fully wired
            for codename in codenames:
                perm = perm_cache.get(codename)
                if perm:
                    RolePermission.objects.get_or_create(
                        role=role, permission=perm, defaults={"id": uuid.uuid4()}
                    )
            continue

        role, _ = Role.objects.get_or_create(
            name=name,
            defaults={
                "id": uuid.uuid4(),
                "description": description,
                "is_internal": is_internal,
                "is_active": True,
                "version": 1,
            },
        )
        for codename in codenames:
            perm = perm_cache.get(codename)
            if perm:
                RolePermission.objects.get_or_create(
                    role=role, permission=perm, defaults={"id": uuid.uuid4()}
                )


def reverse(apps, schema_editor):
    Role = apps.get_model("users", "Role")
    RolePermission = apps.get_model("users", "RolePermission")

    # Reverse rename verifier → verification_officer
    verifier = Role.objects.filter(name="verifier").first()
    if verifier:
        verifier.name = "verification_officer"
        verifier.description = "CLET verification officer — reads and queries credentials."
        verifier.save()

    names_to_remove = ["internal_assessor", "gtec_assessor", "director_general", "auditor"]
    RolePermission.objects.filter(role__name__in=names_to_remove).delete()
    Role.objects.filter(name__in=names_to_remove).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0003_userrole_rolechangeevent_mutualexclusion"),
    ]

    operations = [
        migrations.RunPython(forward, reverse),
    ]
