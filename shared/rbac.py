"""EVS authorisation resolver.

IAM is the authoritative role-assignment store. EVS reads role names from
the JWT (placed there by IAM via Keycloak client roles on evs-api) and maps
them to local permission codenames via its own RolePermission matrix.

Resolution order:
  1. super_admin realm role → wildcard *.
  2. JWT resource_access["evs-api"]["roles"] → filtered against local Role whitelist.
  3. Permission codenames resolved from RolePermission table (60 s cache).

EVS does NOT maintain a UserRole assignment table. Role assignments live in
IAM's UserSystemAssignment and are projected into the JWT by Keycloak.
"""
from __future__ import annotations

import logging

from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

CACHE_TTL = 60
_CACHE_PREFIX = "evs:rbac:role:"

SUPER_ADMIN_ROLE = "super_admin"
WILDCARD = "*"


def _evs_client_id() -> str:
    return getattr(settings, "EVS_CLIENT_ID", "evs-api")


def get_evs_role_names(jwt_payload: dict) -> list[str]:
    """Return the EVS role names carried in the JWT.

    Target: resource_access["evs-api"]["roles"] (client-role model).
    Transitional fallback: realm_access.roles (warns; remove after migration).
    """
    if not jwt_payload:
        return []

    client_id = _evs_client_id()
    resource_roles = (
        jwt_payload.get("resource_access", {}).get(client_id, {}).get("roles")
    )
    if isinstance(resource_roles, list):
        filtered = [
            r for r in resource_roles
            if isinstance(r, str) and not r.startswith("default-roles-")
        ]
        if filtered:
            return filtered

    # Transitional fallback — log so we know when clients still use realm roles
    realm_roles = jwt_payload.get("realm_access", {}).get("roles") or []
    if not isinstance(realm_roles, list):
        return []
    string_roles = [r for r in realm_roles if isinstance(r, str)]
    if string_roles:
        logger.warning(
            "rbac.legacy_realm_role_fallback sub=%s evs_client=%s",
            jwt_payload.get("sub", ""), client_id,
        )
    return string_roles


def _permissions_for_role(role_name: str) -> set[str]:
    """Return permission codenames for *role_name* from cache or DB."""
    cached = cache.get(_CACHE_PREFIX + role_name)
    if cached is not None:
        return set(cached)

    from apps.users.models import RolePermission

    codenames = set(
        RolePermission.objects.filter(
            role__name=role_name, role__is_active=True
        ).values_list("permission__codename", flat=True)
    )
    cache.set(_CACHE_PREFIX + role_name, list(codenames), CACHE_TTL)
    return codenames


def _has_super_admin(jwt_payload: dict) -> bool:
    realm_roles = (jwt_payload or {}).get("realm_access", {}).get("roles") or []
    if not isinstance(realm_roles, list):
        return False
    admin_roles = {
        SUPER_ADMIN_ROLE, "admin", "system_admin",
        "system-admin", "system_administrator",
    }
    return any(role in admin_roles for role in realm_roles)


def permissions_for(jwt_payload: dict) -> set[str]:
    """Return all permission codenames granted to this JWT payload."""
    if _has_super_admin(jwt_payload):
        return {WILDCARD}

    jwt_roles = set(get_evs_role_names(jwt_payload))
    if not jwt_roles:
        return set()

    # Whitelist: only recognise roles EVS has registered locally
    from apps.users.models import Role

    known = set(
        Role.objects.filter(name__in=jwt_roles, is_active=True)
        .values_list("name", flat=True)
    )
    if not known:
        return set()

    result: set[str] = set()
    for role_name in known:
        result |= _permissions_for_role(role_name)
    return result


def has_permission(jwt_payload: dict, codename: str) -> bool:
    granted = permissions_for(jwt_payload)
    return WILDCARD in granted or codename in granted


def invalidate_role(role_name: str) -> None:
    """Bust the permission cache for *role_name* after matrix changes."""
    cache.delete(_CACHE_PREFIX + role_name)
