"""Local profile + EVS permission matrix.

IAM (System 19) owns identity and role assignments. EVS owns:
  * UserProfile  — thin mirror of the Keycloak subject; auto-created on first login.
  * Role         — whitelist of IAM role names EVS recognises. A JWT role not
                   in this table is silently ignored (fail-closed).
  * Permission   — catalog of permission codenames EVS enforces. Seeded via
                   migration; never created at runtime.
  * RolePermission — editable matrix mapping roles → codenames. A
                     system_administrator can change grants without a redeploy;
                     changes propagate within 60 s via the RBAC cache.
"""
import uuid

from django.db import models


class UserProfile(models.Model):
    """Thin local profile. Keycloak / IAM owns authentication and identity.

    Created automatically by shared.auth.KeycloakJWTAuthentication on the
    first authenticated request. Never created manually.
    """

    STATUS_CHOICES = [
        ("active", "Active"),
        ("inactive", "Inactive"),  # Set by IAM deactivation event (future webhook)
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    keycloak_sub = models.UUIDField(
        unique=True, db_index=True, null=True, blank=True,
        help_text="Keycloak subject (JWT sub). Null until first login.",
    )
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="active")
    institution_id = models.UUIDField(
        null=True, blank=True, db_index=True,
        help_text="InstitutionMaster.id — set by a registrar/admin after first login "
                  "for institution_officer and candidate roles.",
    )
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "users_userprofile"
        verbose_name = "User Profile"

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def __str__(self):
        return f"{self.email} ({self.status})"


class Permission(models.Model):
    """A permission codename EVS enforces. Seeded via migration; not user-created."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    codename = models.CharField(max_length=100, unique=True, db_index=True)
    description = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "users_permission"
        ordering = ["codename"]

    def __str__(self):
        return self.codename


class Role(models.Model):
    """EVS-local whitelist of IAM role names this service recognises.

    Mirrors the role names IAM creates on the evs-api Keycloak client.
    A JWT can carry role names not present here — EVS ignores them.
    Permissions are attached via RolePermission; changes propagate in 60 s.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True, db_index=True)
    description = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True)
    is_internal = models.BooleanField(
        default=True,
        help_text="False for institution_officer and candidate (institutions realm).",
    )
    version = models.PositiveIntegerField(
        default=1,
        help_text="Incremented each time the permission matrix for this role changes.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "users_role"
        ordering = ["name"]

    def __str__(self):
        return self.name


class RolePermission(models.Model):
    """Editable grant: role → permission codename.

    The matrix REQ-EVS-F00-02 requires to be configurable at runtime.
    Edits invalidate the 60 s RBAC cache so callers see changes promptly.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="grants")
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE, related_name="grants")
    granted_by = models.UUIDField(null=True, blank=True,
        help_text="keycloak_sub of the system_administrator who granted this.")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "users_rolepermission"
        unique_together = ("role", "permission")
        ordering = ["role__name", "permission__codename"]

    def __str__(self):
        return f"{self.role.name} → {self.permission.codename}"
