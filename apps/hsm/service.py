"""HSM signing service — SoftHSM stub in dev, PKCS#11 in production."""
import logging
import os
import time
from datetime import timedelta

from django.conf import settings

logger = logging.getLogger(__name__)

_PURPOSE_TO_KEY_ENV = {
    "qr_jwt_sign": "HSM_DEV_QR_JWT_SECRET",
    "dg_sign": "HSM_DEV_DG_SIGN_SECRET",
    "credential_sign": "HSM_DEV_CREDENTIAL_SIGN_SECRET",
}

_PURPOSE_TO_KID_SETTING = {
    "qr_jwt_sign": "HSM_KEY_ID_QR_JWT",
    "dg_sign": "HSM_KEY_ID_DG_SIGN",
    "credential_sign": "HSM_KEY_ID_CREDENTIAL_SIGN",
}

_QR_JWT_ISSUER_DEFAULT = "urn:gh:clet:evs"
_QR_JWT_CLOCK_SKEW = timedelta(seconds=300)


def get_active_key_for_purpose(purpose: str):
    from .models import HsmKey
    return HsmKey.objects.filter(purpose=purpose, is_active=True).order_by("-created_at").first()


def sign_payload(*, purpose: str, payload: dict) -> dict:
    """Sign *payload* dict and return {token, kid, algorithm}.

    In dev (HSM_ENABLED=False): HS256 software signing via env-var secret.
    In prod (HSM_ENABLED=True): delegates to PKCS#11 via SoftHSM / HSM appliance.
    """
    if getattr(settings, "HSM_ENABLED", False):
        return _sign_pkcs11(purpose=purpose, payload=payload)
    return _sign_software(purpose=purpose, payload=payload)


def verify_qr_token(token: str) -> dict:
    """Verify a QR JWT and return its decoded claims.

    Applies a 5-minute clock-skew leeway (EVS-F03 requirement).
    Raises jwt.InvalidTokenError on failure.
    """
    import jwt as _jwt

    if getattr(settings, "HSM_ENABLED", False):
        raise NotImplementedError("PKCS#11 QR verify not yet implemented.")

    secret_env = _PURPOSE_TO_KEY_ENV["qr_jwt_sign"]
    secret = os.environ.get(secret_env, f"dev-qr_jwt_sign-secret-key-change-in-prod")
    issuer = getattr(settings, "EVS_QR_JWT_ISSUER", _QR_JWT_ISSUER_DEFAULT)
    return _jwt.decode(
        token, secret, algorithms=["HS256"],
        options={"leeway": _QR_JWT_CLOCK_SKEW},
        issuer=issuer,
    )


# ── Private ───────────────────────────────────────────────────────────────────

def _sign_software(*, purpose: str, payload: dict) -> dict:
    import jwt as _jwt

    secret_env = _PURPOSE_TO_KEY_ENV.get(purpose)
    if not secret_env:
        raise ValueError(f"Unknown signing purpose: {purpose!r}")

    secret = os.environ.get(secret_env, f"dev-{purpose}-secret-key-change-in-prod")
    kid_setting = _PURPOSE_TO_KID_SETTING.get(purpose, f"HSM_KEY_ID_{purpose.upper()}")
    kid = getattr(settings, kid_setting, f"evs-{purpose}-v1")
    issuer = getattr(settings, "EVS_QR_JWT_ISSUER", _QR_JWT_ISSUER_DEFAULT)

    claims = {
        "iss": issuer,
        "iat": int(time.time()),
        **payload,
    }
    token = _jwt.encode(claims, secret, algorithm="HS256", headers={"kid": kid})
    return {"token": token, "kid": kid, "algorithm": "HS256"}


def sign_with_key(*, key_id: str, payload: bytes) -> str:
    """Sign *payload* bytes with the named HSM key. Returns base64-encoded signature.

    In dev: HMAC-SHA256 with a derived dev secret.
    In prod: delegates to PKCS#11.
    """
    import base64, hashlib, hmac
    if getattr(settings, "HSM_ENABLED", False):
        raise NotImplementedError("PKCS#11 sign_with_key not yet implemented.")
    secret = os.environ.get("HSM_DEV_DG_SIGN_SECRET", "dev-dg-sign-secret-change-in-prod")
    sig = hmac.new(secret.encode(), payload, hashlib.sha256).digest()
    return base64.b64encode(sig).decode()


def _sign_pkcs11(*, purpose: str, payload: dict) -> dict:
    raise NotImplementedError(
        "PKCS#11 signing not yet implemented. Set HSM_ENABLED=False in development."
    )
