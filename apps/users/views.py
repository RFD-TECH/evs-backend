"""EVS Users API views.

Scope: profile lookup + permission-matrix management only.
Role assignments are managed by IAM (System 19), not EVS.
"""
import logging

from django.shortcuts import get_object_or_404
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet

from shared.exceptions import error_response, success_response
from shared.pagination import StandardResultsPagination
from shared.permissions import check_permission

from .models import Role, RolePermission, UserProfile
from .serializers import (
    PermissionSerializer, RolePermissionGrantSerializer,
    RoleSerializer, UserProfileLinkSerializer, UserProfileSerializer,
)

logger = logging.getLogger(__name__)


class UserProfileViewSet(GenericViewSet):
    """Read user profiles and link them to institutions.

    Profiles are created automatically by the auth layer on first login.
    Role assignments are managed by IAM — use the IAM admin API to grant
    or revoke roles.
    """

    pagination_class = StandardResultsPagination

    def get_queryset(self):
        return UserProfile.objects.order_by("-created_at")

    def list(self, request):
        if not check_permission(request, "user:read"):
            return error_response("Forbidden", status=403)

        qs = self.get_queryset()
        if inst := request.query_params.get("institution_id"):
            qs = qs.filter(institution_id=inst)
        if st := request.query_params.get("status"):
            qs = qs.filter(status=st)

        page = self.paginate_queryset(qs)
        if page is not None:
            data = UserProfileSerializer(page, many=True, context={"request": request}).data
            return self.get_paginated_response(data)
        return Response(UserProfileSerializer(qs, many=True, context={"request": request}).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "user:read"):
            return error_response("Forbidden", status=403)
        profile = get_object_or_404(self.get_queryset(), pk=pk)
        return Response(UserProfileSerializer(profile, context={"request": request}).data)

    @action(detail=True, methods=["patch"], url_path="link-institution")
    def link_institution(self, request, pk=None):
        """PATCH /v1/users/{id}/link-institution — assign institution_id.

        Called by a registrar or system_administrator after an institution
        officer or candidate logs in for the first time.
        """
        if not check_permission(request, "institution:manage"):
            return error_response("Forbidden", status=403)

        profile = get_object_or_404(self.get_queryset(), pk=pk)
        serializer = UserProfileLinkSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)

        profile.institution_id = serializer.validated_data["institution_id"]
        profile.save(update_fields=["institution_id", "updated_at"])
        return success_response(UserProfileSerializer(profile, context={"request": request}).data)


class RoleViewSet(GenericViewSet):
    """Role catalog + runtime permission-matrix management.

    Role names are owned by IAM. EVS owns which codenames each role
    is permitted to exercise (the RolePermission matrix).
    Only system_administrator can modify the matrix.
    """

    def list(self, request):
        if not check_permission(request, "user:read"):
            return error_response("Forbidden", status=403)
        roles = Role.objects.prefetch_related("grants__permission").filter(is_active=True)
        return Response(RoleSerializer(roles, many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "user:read"):
            return error_response("Forbidden", status=403)
        role = get_object_or_404(Role, pk=pk)
        return Response(RoleSerializer(role).data)

    @action(detail=True, methods=["post"], url_path="permissions/grant")
    def grant_permission(self, request, pk=None):
        """Add a codename to this role's permission set."""
        if not check_permission(request, "role:manage"):
            return error_response("Forbidden", status=403)

        role = get_object_or_404(Role, pk=pk)
        serializer = RolePermissionGrantSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)

        from .models import Permission
        perm = get_object_or_404(Permission, codename=serializer.validated_data["codename"])
        RolePermission.objects.get_or_create(
            role=role, permission=perm,
            defaults={"granted_by": getattr(request.user, "keycloak_sub", None)},
        )
        role.version += 1
        role.save(update_fields=["version", "updated_at"])

        from shared.rbac import invalidate_role
        invalidate_role(role.name)

        return success_response(RoleSerializer(role).data)

    @action(detail=True, methods=["post"], url_path="permissions/revoke")
    def revoke_permission(self, request, pk=None):
        """Remove a codename from this role's permission set."""
        if not check_permission(request, "role:manage"):
            return error_response("Forbidden", status=403)

        role = get_object_or_404(Role, pk=pk)
        serializer = RolePermissionGrantSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)

        deleted, _ = RolePermission.objects.filter(
            role=role, permission__codename=serializer.validated_data["codename"]
        ).delete()
        if not deleted:
            return error_response("Permission grant not found.", status=404)

        role.version += 1
        role.save(update_fields=["version", "updated_at"])

        from shared.rbac import invalidate_role
        invalidate_role(role.name)

        return success_response(RoleSerializer(role).data)

    @action(detail=False, methods=["get"])
    def permissions(self, request):
        """List all known permission codenames (the seeded catalog)."""
        if not check_permission(request, "user:read"):
            return error_response("Forbidden", status=403)
        from .models import Permission
        return Response(PermissionSerializer(Permission.objects.all(), many=True).data)


class PermissionCheckView(APIView):
    """GET /v1/permissions/check?codename=<codename>

    Dry-run: returns whether the calling user holds the requested permission.
    Never modifies state; safe for other services to call as an authz probe.
    """

    def get(self, request):
        auth = getattr(request, "auth", None)
        if not auth:
            return error_response("Authentication required.", status=401)

        codename = request.query_params.get("codename", "").strip()
        if not codename:
            return error_response("Query parameter 'codename' is required.", status=400)

        from shared.rbac import has_permission
        allowed = has_permission(auth, codename)
        return Response({
            "codename": codename,
            "allowed": allowed,
            "sub": str(auth.get("sub", "")),
        })
