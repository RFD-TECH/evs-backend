from django.apps import AppConfig


class LegacyMigrationConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.legacy_migration"
    label = "legacy_migration"
    verbose_name = "Legacy Migration"
