"""JWT authentication for EVS (System 03).

Two modes switched by ``settings.KEYCLOAK_ENABLED``:

* Production (RS256): validates Keycloak tokens from two realms —
  ``clet-internal`` (staff) and ``institutions`` (Institution Officers).
* Dev (HS256): validates tokens signed with ``settings.JWT_SECRET_KEY``.

On success ``request.auth`` carries the decoded JWT payload;
``request.user`` is a thin ``UserProfile`` mirror.
"""
from __future__ import annotations

import json
import logging

import jwt
import requests

from django.conf import settings
from django.core.cache import cache
from jwt.algorithms import RSAAlgorithm
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

logger = logging.getLogger(__name__)

JWKS_CACHE_SECONDS = 300


def _categorise(message: str) -> str:
    low = (message or "").lower()
    if "expired" in low:
        return "auth_token_expired"
    if "audience" in low or "aud" in low:
        return "auth_audience_mismatch"
    return "auth_token_invalid"


def _normalise_url(url: str) -> str:
    return (url or "").rstrip("/")


def _fetch_jwks(realm_url: str) -> dict:
    cache_key = f"evs:keycloak:jwks:{realm_url}"
    jwks = cache.get(cache_key)
    if jwks:
        return jwks
    response = requests.get(
        f"{realm_url}/protocol/openid-connect/certs",
        timeout=5,
    )
    response.raise_for_status()
    jwks = response.json()
    cache.set(cache_key, jwks, timeout=JWKS_CACHE_SECONDS)
    return jwks


def _signing_key(realm_url: str, kid: str):
    jwks = _fetch_jwks(realm_url)
    for key_data in jwks.get("keys", []):
        if key_data.get("kid") == kid:
            return RSAAlgorithm.from_jwk(json.dumps(key_data))
    cache.delete(f"evs:keycloak:jwks:{realm_url}")
    jwks = _fetch_jwks(realm_url)
    for key_data in jwks.get("keys", []):
        if key_data.get("kid") == kid:
            return RSAAlgorithm.from_jwk(json.dumps(key_data))
    raise AuthenticationFailed("Token signing key not found.")


def _decode_rs256(token: str) -> dict:
    try:
        header = jwt.get_unverified_header(token)
        unverified = jwt.decode(token, options={"verify_signature": False}, algorithms=["RS256"])
    except Exception as exc:
        raise AuthenticationFailed("Invalid token format.") from exc

    iss = _normalise_url(unverified.get("iss", ""))
    internal_url = _normalise_url(getattr(settings, "KEYCLOAK_REALM_INTERNAL_URL", ""))
    institutions_url = _normalise_url(getattr(settings, "KEYCLOAK_REALM_INSTITUTIONS_URL", ""))

    if not internal_url or not institutions_url:
        raise AuthenticationFailed("Keycloak realm URLs are not fully configured.")

    def _match(token_iss, expected):
        return token_iss == expected or token_iss.replace("localhost", "keycloak") == expected.replace("localhost", "keycloak")

    if _match(iss, internal_url):
        realm_url = internal_url
    elif _match(iss, institutions_url):
        realm_url = institutions_url
    else:
        raise AuthenticationFailed("Token issuer not recognised.")

    key = _signing_key(realm_url, header.get("kid", ""))
    audiences = [a for a in getattr(settings, "KEYCLOAK_VALID_AUDIENCES", []) or [] if a]
    decode_kwargs: dict = {"key": key, "algorithms": ["RS256"], "options": {"verify_iss": False}}
    if audiences:
        decode_kwargs["audience"] = audiences
    else:
        decode_kwargs["options"]["verify_aud"] = False

    try:
        return jwt.decode(token, **decode_kwargs)
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationFailed("Token has expired.") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthenticationFailed(f"Token validation failed: {exc}") from exc


def _decode_hs256(token: str) -> dict:
    try:
        return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationFailed("Token has expired.") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthenticationFailed(f"Invalid token: {exc}") from exc


class KeycloakJWTAuthentication(BaseAuthentication):
    """DRF authentication backend for EVS.

    RS256 tokens → Keycloak validation (two realms: internal staff + institutions).
    HS256 tokens → dev fallback (rejected when KEYCLOAK_ENABLED=True).
    """

    def authenticate(self, request):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None

        token = auth_header.split(" ", 1)[1].strip()
        if not token:
            return None

        try:
            alg = jwt.get_unverified_header(token).get("alg")
        except Exception as exc:
            self._record_failure(request, "auth_token_invalid", reason=str(exc))
            raise AuthenticationFailed("Invalid token format.") from exc

        try:
            if alg == "RS256":
                payload = _decode_rs256(token)
            elif alg == "HS256":
                if settings.KEYCLOAK_ENABLED:
                    raise AuthenticationFailed("HS256 tokens are not accepted in Keycloak mode.")
                payload = _decode_hs256(token)
            else:
                raise AuthenticationFailed(
                    f"Unsupported signing algorithm: {alg}. Use the RS256 Keycloak access_token."
                )
        except AuthenticationFailed as exc:
            self._record_failure(request, _categorise(str(exc)), reason=str(exc))
            raise

        payload.setdefault("sub", payload.get("user_id", ""))
        if "realm_access" not in payload:
            single = payload.get("role")
            roles = single if isinstance(single, list) else ([single] if single else [])
            payload["realm_access"] = {"roles": roles}

        user = self._mirror_profile(payload)
        return user, payload

    def authenticate_header(self, request):
        return "Bearer"

    @staticmethod
    def _record_failure(request, category, *, reason: str = "") -> None:
        try:
            from shared.secops import record_security_event
            record_security_event(
                category=category,
                ip_address=getattr(request, "ip_address", None) or request.META.get("REMOTE_ADDR"),
                request_id=getattr(request, "request_id", None),
                indicators={"path": request.path, "method": request.method, "reason": reason[:200]},
            )
        except Exception:
            pass

    def _mirror_profile(self, payload: dict):
        from apps.users.models import UserProfile, Role, UserRole, RoleChangeEvent, RoleMutualExclusion
        from apps.audit.models import AuditEvent
        from django.db import transaction
        from django.utils import timezone

        sub = payload.get("sub")
        if not sub:
            raise AuthenticationFailed("Token subject missing.")

        email = payload.get("email", "")
        first_name = payload.get("given_name", "")
        last_name = payload.get("family_name", "")
        if not first_name and not last_name and payload.get("name"):
            parts = payload["name"].split(" ", 1)
            first_name = parts[0]
            last_name = parts[1] if len(parts) > 1 else ""

        from shared.rbac import get_evs_role_names
        token_roles = get_evs_role_names(payload)

        with transaction.atomic():
            user = UserProfile.objects.select_for_update().filter(keycloak_sub=sub).first()

            if not user and email:
                user = (
                    UserProfile.objects.select_for_update()
                    .filter(email__iexact=email, keycloak_sub__isnull=True)
                    .first()
                )
                if user:
                    user.keycloak_sub = sub
                    user.status = "active"
                    if first_name and not user.first_name:
                        user.first_name = first_name
                    if last_name and not user.last_name:
                        user.last_name = last_name
                    user.save()

            if not user:
                preferred = payload.get("preferred_username", "")
                is_service_account = preferred.startswith("service-account-") or bool(
                    payload.get("azp") and not email
                )
                if is_service_account:
                    display_name = preferred.replace("service-account-", "", 1)
                    user = UserProfile.objects.create(
                        keycloak_sub=sub,
                        email=email or f"{display_name}@service.internal",
                        first_name=display_name,
                        last_name="(service)",
                        status="active",
                        metadata={"is_service_account": True, "client_id": payload.get("azp", "")},
                    )
                    AuditEvent.record(
                        actor_id=sub,
                        action="SERVICE_ACCOUNT_PROFILE_CREATED",
                        entity_type="user",
                        entity_id=str(user.id),
                        new_state={"status": "active"},
                    )
                else:
                    if not email:
                        raise AuthenticationFailed("Human-user token must contain an email claim.")
                    user = UserProfile.objects.create(
                        keycloak_sub=sub, email=email,
                        first_name=first_name, last_name=last_name, status="active",
                    )
                    AuditEvent.record(
                        actor_id=sub, action="AUTO_PROFILE_CREATED",
                        entity_type="user", entity_id=str(user.id),
                        new_state={"email": email, "status": "active"},
                    )

            # Sync roles from JWT
            today = timezone.now().date()
            now_ts = timezone.now()
            norm_token_roles = {r.lower().replace("-", "_") for r in token_roles}

            for ur in UserRole.objects.filter(user=user, revoked_at__isnull=True):
                if ur.role.name not in norm_token_roles:
                    ur.revoked_at = now_ts
                    ur.revoke_reason = "Sync from JWT token (role removed in IAM)"
                    ur.save()
                    RoleChangeEvent.objects.create(
                        user=user, role=ur.role, change_type="revoke",
                        reason="Sync from JWT token (role removed in IAM)", occurred_at=now_ts,
                    )

            for role_name in token_roles:
                norm_name = role_name.lower().replace("-", "_")
                role_obj = Role.objects.filter(name=norm_name, is_active=True).first()
                if not role_obj:
                    continue
                conflict = RoleMutualExclusion.check_conflict(user, role_obj)
                if conflict:
                    logger.warning("auth: skipping conflicting role %s for sub=%s", norm_name, sub)
                    continue
                if not UserRole.objects.filter(user=user, role=role_obj, revoked_at__isnull=True).exists():
                    UserRole.objects.create(user=user, role=role_obj, effective_from=today, created_at=now_ts)
                    RoleChangeEvent.objects.create(
                        user=user, role=role_obj, change_type="assign",
                        reason="Auto-sync from JWT token", occurred_at=now_ts,
                    )

        return user
