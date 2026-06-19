"""EVS (System 03) — base settings."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent

SECRET_KEY = os.environ.get("SECRET_KEY", "evs-dev-secret-key-change-before-production")
DEBUG = os.environ.get("DEBUG", "False") == "True"
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "*").split(",")

# ── Apps ─────────────────────────────────────────────────────────────
DJANGO_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.postgres",
]

THIRD_PARTY_APPS = [
    "rest_framework",
    "corsheaders",
    "django_filters",
    "drf_spectacular",
    "django_celery_beat",
    "django_fsm",
]

LOCAL_APPS = [
    "shared.apps.SharedConfig",
    "apps.audit.apps.AuditConfig",
    "apps.users.apps.UsersConfig",
    "apps.hsm.apps.HsmConfig",
    "apps.institutions.apps.InstitutionsConfig",
    "apps.registry.apps.RegistryConfig",
    "apps.verification.apps.VerificationConfig",
    "apps.connectors.apps.ConnectorsConfig",
    "apps.foreign_credentials.apps.ForeignCredentialsConfig",
    "apps.notifications.apps.NotificationsConfig",
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

# ── Middleware ────────────────────────────────────────────────────────
MIDDLEWARE = [
    "shared.middleware.JsonExceptionMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "shared.middleware.AuditMiddleware",
    "shared.middleware.EdgeRateLimitMiddleware",
    "shared.middleware.IdempotencyKeyMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# ── Database ──────────────────────────────────────────────────────────
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends." + os.environ.get("DBENGINE", "sqlite3"),
        "NAME": os.environ.get("DBNAME", BASE_DIR / "db.sqlite3"),
        "USER": os.environ.get("DBUSER", ""),
        "PASSWORD": os.environ.get("DBPASSWORD", ""),
        "HOST": os.environ.get("EVS_DBHOST", os.environ.get("DBHOST", "")),
        "PORT": os.environ.get("DBPORT", ""),
        "CONN_MAX_AGE": int(os.environ.get("CONN_MAX_AGE", "60")),
    }
}

# ── Cache / Redis ─────────────────────────────────────────────────────
REDIS_URL = os.environ.get("EVS_REDIS_URL", os.environ.get("REDIS_URL", "redis://localhost:6379/0"))

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": REDIS_URL,
        "KEY_PREFIX": "evs",
    }
}

# ── DRF ──────────────────────────────────────────────────────────────
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ("shared.auth.KeycloakJWTAuthentication",),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "EXCEPTION_HANDLER": "shared.exceptions.evs_exception_handler",
    "DEFAULT_FILTER_BACKENDS": (
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ),
    "DEFAULT_PAGINATION_CLASS": "shared.pagination.StandardResultsPagination",
    "PAGE_SIZE": 20,
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

# ── Auth / Password ───────────────────────────────────────────────────
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

# ── Keycloak / JWT ────────────────────────────────────────────────────
KEYCLOAK_ENABLED = os.environ.get("KEYCLOAK_ENABLED", "False") == "True"
_keycloak_base = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080").rstrip("/")
KEYCLOAK_REALM_INTERNAL_URL = (
    f"{_keycloak_base}/realms/{os.environ.get('KEYCLOAK_REALM_INTERNAL', 'clet-internal')}"
)
KEYCLOAK_REALM_INSTITUTIONS_URL = (
    f"{_keycloak_base}/realms/{os.environ.get('KEYCLOAK_REALM_INSTITUTIONS', 'institutions')}"
)
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", SECRET_KEY)
JWT_ALGORITHM = "HS256"
EVS_CLIENT_ID = os.environ.get("EVS_CLIENT_ID", "evs-api")
EVS_CLIENT_SECRET = os.environ.get("EVS_CLIENT_SECRET", "")
KEYCLOAK_VALID_AUDIENCES = [
    a for a in os.environ.get("KEYCLOAK_VALID_AUDIENCES", EVS_CLIENT_ID).split(",") if a
]

# Step-up authentication (DG signing, Registrar fraud confirm)
STEP_UP_HEADER_MFA = "HTTP_X_MFA_VERIFIED"
STEP_UP_HEADER_ACR = "HTTP_X_ACR"
STEP_UP_MIN_ACR_LEVEL = 2

# ── Celery ────────────────────────────────────────────────────────────
CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = REDIS_URL
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_TIMEZONE = "Africa/Accra"
CELERY_BEAT_SCHEDULER = "django_celery_beat.schedulers:DatabaseScheduler"

CELERY_TASK_QUEUES = {
    "high-priority": {},
    "normal": {},
    "sla-monitor": {},
    "integrity-sweep": {},
    "outbox": {},
    "notifications": {},
    "fraud-detection": {},
}

# ── External Systems ──────────────────────────────────────────────────
SYSTEM_17_URL = os.environ.get("SYSTEM_17_URL", "")
SYSTEM_17_HMAC_SECRET = os.environ.get("SYSTEM_17_HMAC_SECRET", "")
SYSTEM_17_TIMEOUT_SECONDS = float(os.environ.get("SYSTEM_17_TIMEOUT_SECONDS", "5"))
SYSTEM_17_NONCE_WINDOW_SECONDS = int(os.environ.get("SYSTEM_17_NONCE_WINDOW_SECONDS", "300"))

SYSTEM_21_URL = os.environ.get("SYSTEM_21_URL", "")
SYSTEM_21_API_KEY = os.environ.get("SYSTEM_21_API_KEY", "")

CALS_URL = os.environ.get("CALS_URL", "http://cals:8000")
CALS_HMAC_SECRET = os.environ.get("CALS_HMAC_SECRET", "")

IAM_INTERNAL_URL = os.environ.get("IAM_INTERNAL_URL", "http://iam:8001")

# ── HSM ───────────────────────────────────────────────────────────────
HSM_ENABLED = os.environ.get("HSM_ENABLED", "False") == "True"
HSM_PKCS11_LIB = os.environ.get("HSM_PKCS11_LIB", "/usr/lib/softhsm/libsofthsm2.so")
HSM_SLOT = int(os.environ.get("HSM_SLOT", "0"))
HSM_PIN = os.environ.get("HSM_PIN", "")
HSM_KEY_ID_QR_JWT = os.environ.get("HSM_KEY_ID_QR_JWT", "evs-qr-jwt-v1")
HSM_KEY_ID_DG_SIGN = os.environ.get("HSM_KEY_ID_DG_SIGN", "evs-dg-sign-v1")
HSM_KEY_ID_CREDENTIAL_SIGN = os.environ.get("HSM_KEY_ID_CREDENTIAL_SIGN", "evs-cred-sign-v1")

# ── EVS Feature Flags ─────────────────────────────────────────────────
EVS_QR_VERIFICATION_ENABLED = os.environ.get("EVS_QR_VERIFICATION_ENABLED", "True") == "True"
EVS_PDF_VERIFICATION_ENABLED = os.environ.get("EVS_PDF_VERIFICATION_ENABLED", "False") == "True"
EVS_WAEC_ENABLED = os.environ.get("EVS_WAEC_ENABLED", "False") == "True"
EVS_FOREIGN_ASSESSMENT_ENABLED = os.environ.get("EVS_FOREIGN_ASSESSMENT_ENABLED", "False") == "True"
EVS_FRAUD_DETECTION_ENABLED = os.environ.get("EVS_FRAUD_DETECTION_ENABLED", "False") == "True"
EVS_LEGACY_MIGRATION_ENABLED = os.environ.get("EVS_LEGACY_MIGRATION_ENABLED", "False") == "True"

# ── EVS Rate-Limit Thresholds ─────────────────────────────────────────
EDGE_THROTTLE_THRESHOLD = int(os.environ.get("EDGE_THROTTLE_THRESHOLD", "100"))
EDGE_BLOCK_THRESHOLD_24H = int(os.environ.get("EDGE_BLOCK_THRESHOLD_24H", "1000"))
IDEMPOTENCY_CACHE_TTL_SECONDS = int(os.environ.get("IDEMPOTENCY_CACHE_TTL_SECONDS", "86400"))
EDGE_SECURITY_EVENT_RETENTION_DAYS = int(os.environ.get("EDGE_SECURITY_EVENT_RETENTION_DAYS", "90"))

# ── EVS Business Rules ────────────────────────────────────────────────
EVS_BATCH_MAX_RECORDS = int(os.environ.get("EVS_BATCH_MAX_RECORDS", "10000"))
EVS_BATCH_MAX_MB = int(os.environ.get("EVS_BATCH_MAX_MB", "100"))
EVS_UPLOAD_SLA_DAYS = int(os.environ.get("EVS_UPLOAD_SLA_DAYS", "30"))
EVS_REVOCATION_CACHE_TTL_SECONDS = int(os.environ.get("EVS_REVOCATION_CACHE_TTL_SECONDS", "60"))
EVS_QR_JWT_ALGORITHM = os.environ.get("EVS_QR_JWT_ALGORITHM", "HS256")
EVS_QR_JWT_SECRET = os.environ.get("EVS_QR_JWT_SECRET", SECRET_KEY)
EVS_QR_JWT_ISSUER = os.environ.get("EVS_QR_JWT_ISSUER", "https://evs.clet.gov.gh")
EVS_VERIFY_BASE_URL = os.environ.get("EVS_VERIFY_BASE_URL", "https://evs.clet.gov.gh/verify")
EVS_FOREIGN_EQUIVALENCE_MIN_WORDS = int(os.environ.get("EVS_FOREIGN_EQUIVALENCE_MIN_WORDS", "100"))
EVS_FRAUD_RESOLUTION_MIN_WORDS = int(os.environ.get("EVS_FRAUD_RESOLUTION_MIN_WORDS", "30"))

# ── MinIO / Object Storage ────────────────────────────────────────────
MINIO_ENABLED = os.environ.get("MINIO_ENABLED", "False") == "True"
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "")
MINIO_BUCKET_NAME = os.environ.get("MINIO_BUCKET_NAME", "evs-bucket")
MINIO_SECURE = os.environ.get("MINIO_SECURE", "False") == "True"

# ── Internationalisation ──────────────────────────────────────────────
LANGUAGE_CODE = "en-us"
TIME_ZONE = os.environ.get("TIME_ZONE", "Africa/Accra")
USE_I18N = True
USE_TZ = True

# ── Static Files ──────────────────────────────────────────────────────
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ── CORS ──────────────────────────────────────────────────────────────
CORS_ALLOWED_ORIGINS = [o for o in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",") if o.strip()]
CORS_ALLOW_ALL_ORIGINS = DEBUG

# ── OpenAPI / Spectacular ─────────────────────────────────────────────
SPECTACULAR_SETTINGS = {
    "TITLE": "EVS API — System 03",
    "DESCRIPTION": "Examination Verification System: Verified Credential Registry & Cryptographic Verification",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
}
