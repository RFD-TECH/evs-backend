"""EVS users serializers."""
from rest_framework import serializers

from .models import Permission, Role, RolePermission, UserProfile


class UserProfileSerializer(serializers.ModelSerializer):
    roles = serializers.SerializerMethodField()

    class Meta:
        model = UserProfile
        fields = [
            "id", "keycloak_sub", "email", "first_name", "last_name",
            "status", "institution_id", "metadata", "created_at", "updated_at",
            "roles",
        ]
        read_only_fields = [
            "id", "keycloak_sub", "email", "first_name", "last_name",
            "status", "created_at", "updated_at", "roles",
        ]

    def get_roles(self, obj):
        """Return EVS role names from the JWT stored in context, not from a DB table."""
        request = self.context.get("request")
        if request and hasattr(request, "auth") and request.auth:
            from shared.rbac import get_evs_role_names
            return get_evs_role_names(request.auth)
        return []


class UserProfileLinkSerializer(serializers.Serializer):
    """Used by PATCH /v1/users/{id}/ to link a profile to an institution."""
    institution_id = serializers.UUIDField(allow_null=True)


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ["id", "codename", "description", "created_at"]
        read_only_fields = fields


class RoleSerializer(serializers.ModelSerializer):
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = Role
        fields = [
            "id", "name", "description", "is_active", "is_internal",
            "version", "created_at", "permissions",
        ]
        read_only_fields = fields

    def get_permissions(self, obj):
        return list(obj.grants.values_list("permission__codename", flat=True))


class RolePermissionGrantSerializer(serializers.Serializer):
    codename = serializers.CharField(max_length=100)

    def validate_codename(self, value):
        if not Permission.objects.filter(codename=value).exists():
            raise serializers.ValidationError(
                f"Unknown permission codename '{value}'. "
                "Codenames are seeded via migration; they cannot be created at runtime."
            )
        return value
