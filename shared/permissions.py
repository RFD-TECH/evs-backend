"""DRF permission classes for EVS."""
from __future__ import annotations

from rest_framework.permissions import BasePermission


class HasPermission(BasePermission):
    """Require a specific EVS permission codename."""

    def __init__(self, codename: str):
        self.codename = codename

    def has_permission(self, request, view):
        if not request.auth:
            return False
        from shared.rbac import has_permission
        return has_permission(request.auth, self.codename)

    def __call__(self):
        return self


def has_permission(codename: str) -> "HasPermission":
    """Factory: ``permission_classes = [IsAuthenticated, has_permission('registry:batch:write')]``"""

    class _Perm(BasePermission):
        def has_permission(self, request, view):
            if not request.auth:
                return False
            from shared.rbac import has_permission as _hp
            return _hp(request.auth, codename)

    _Perm.__name__ = f"HasPermission({codename})"
    return _Perm


class IsServiceAccount(BasePermission):
    """Allow only Keycloak service-account tokens (machine-to-machine calls)."""

    def has_permission(self, request, view):
        if not request.auth:
            return False
        preferred = request.auth.get("preferred_username", "")
        return preferred.startswith("service-account-") or bool(
            request.auth.get("azp") and not request.auth.get("email")
        )


class IsStepUpVerified(BasePermission):
    """Require step-up MFA header (DG signing, Registrar fraud confirm)."""

    def has_permission(self, request, view):
        from django.conf import settings
        return request.META.get(settings.STEP_UP_HEADER_MFA, "") == "true"


def check_permission(request, codename: str) -> bool:
    """Inline boolean permission check for use inside view method bodies.

    Usage::

        if not check_permission(request, "credential:read"):
            return error_response("Forbidden", status=403)
    """
    auth = getattr(request, "auth", None)
    if not auth:
        return False
    from shared.rbac import has_permission as _hp
    result = _hp(auth, codename)
    if not result:
        try:
            from shared.secops import record_security_event
            record_security_event(
                category="authz_denied",
                severity="warning",
                ip_address=getattr(request, "ip_address", None) or request.META.get("REMOTE_ADDR"),
                actor_id=str(auth.get("sub", "")) or None,
                request_id=getattr(request, "request_id", None),
                indicators={"codename": codename, "path": request.path, "method": request.method},
            )
        except Exception:
            pass
    return result
