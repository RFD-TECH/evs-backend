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


class UserRole(models.Model):
    """Live role assignment — which EVS roles a user currently holds.

    Created/revoked by shared.auth on every authenticated request when the
    JWT role list diverges from the local table. Append-only in spirit:
    revocation sets revoked_at rather than deleting the row.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name="role_assignments")
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="assignments")
    effective_from = models.DateField()
    effective_to = models.DateField(null=True, blank=True)
    granted_by = models.UUIDField(null=True, blank=True,
        help_text="keycloak_sub of the actor who granted this assignment.")
    justification = models.CharField(max_length=500, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoke_reason = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField()

    class Meta:
        db_table = "users_userrole"
        indexes = [
            models.Index(fields=["user", "revoked_at"], name="userrole_user_active_idx"),
        ]

    def __str__(self):
        status = "active" if self.revoked_at is None else "revoked"
        return f"{self.user.email} / {self.role.name} ({status})"


class RoleChangeEvent(models.Model):
    """Append-only audit log for role grants and revocations.

    Written by shared.auth during JWT sync; never updated or deleted.
    """

    CHANGE_TYPE_ASSIGN = "assign"
    CHANGE_TYPE_REVOKE = "revoke"
    CHANGE_TYPE_CHOICES = [
        (CHANGE_TYPE_ASSIGN, "Assign"),
        (CHANGE_TYPE_REVOKE, "Revoke"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name="role_change_events")
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="change_events")
    change_type = models.CharField(max_length=20, choices=CHANGE_TYPE_CHOICES)
    reason = models.CharField(max_length=500, blank=True)
    occurred_at = models.DateTimeField()

    class Meta:
        db_table = "users_rolechangeevent"
        ordering = ["-occurred_at"]

    def __str__(self):
        return f"{self.change_type} {self.role.name} → {self.user.email} @ {self.occurred_at}"


class RoleMutualExclusion(models.Model):
    """Pairs of roles that cannot coexist on the same user (SoD enforcement).

    Checked by shared.auth before granting a new role during JWT sync.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    role_a = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="exclusions_as_a")
    role_b = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="exclusions_as_b")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "users_rolemutualexclusion"
        unique_together = ("role_a", "role_b")

    def __str__(self):
        return f"{self.role_a.name} ⊗ {self.role_b.name}"

    @classmethod
    def check_conflict(cls, user, role):
        """Return the conflicting Role if assigning `role` to `user` would violate a
        mutual exclusion rule, else return None."""
        from django.db.models import Q
        active_role_ids = list(
            UserRole.objects.filter(user=user, revoked_at__isnull=True).values_list("role_id", flat=True)
        )
        if not active_role_ids:
            return None
        exclusion = cls.objects.filter(
            Q(role_a=role, role_b_id__in=active_role_ids) |
            Q(role_b=role, role_a_id__in=active_role_ids)
        ).first()
        if exclusion is None:
            return None
        return exclusion.role_b if exclusion.role_a_id == role.pk else exclusion.role_a
