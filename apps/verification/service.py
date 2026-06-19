"""QR verification service — EVS-F03-01 through EVS-F03-05.

Flow:
  1. Decode and validate the QR JWT signature (HSM JWKS or dev HS256).
  2. Verify the JWT sub claim matches the URL credential_id.
  3. Fetch the credential from the registry.
  4. Re-compute SHA-256 tamper seal — BEFORE status checks (Tampered > Revoked).
  5. Check revocation via cache (60 s freshness), then status field.
  6. Log a VerificationSession and publish audit event via outbox.
  7. Return a structured result dict — target latency ≤2000 ms.
"""
import hashlib
import hmac
import logging
import time

logger = logging.getLogger(__name__)

_REVOCATION_CACHE_TTL = 60  # seconds


def _hashes_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def _is_revoked_cached(credential_id: str) -> bool:
    """Check the RevocationRecord table with a 60-second in-process cache."""
    from django.core.cache import cache
    cache_key = f"evs:revoked:{credential_id}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached
    from apps.registry.models import RevocationRecord
    revoked = RevocationRecord.objects.filter(credential_id=credential_id).exists()
    cache.set(cache_key, revoked, _REVOCATION_CACHE_TTL)
    return revoked


def verify_credential(
    *,
    credential_id: str,
    token: str,
    ip: str = "",
    user_agent: str = "",
    verifier_id=None,
    channel: str = "qr_scan",
    device_fingerprint: str = "",
) -> dict:
    """Perform a full QR verification and return a structured result dict."""
    start = time.monotonic()
    payload_hash = hashlib.sha256(token.encode()).hexdigest() if token else ""
    checks: list[str] = []

    # ── Step 1: Validate JWT ──────────────────────────────────────────────────
    import jwt as _jwt
    from apps.hsm.service import verify_qr_token

    jwt_kid = ""
    try:
        header = _jwt.get_unverified_header(token)
        jwt_kid = header.get("kid", "")
        claims = verify_qr_token(token)
        checks.append("jwt_signature")
    except _jwt.ExpiredSignatureError:
        return _log_and_return(
            credential_id=credential_id, credential=None,
            result="token_expired",
            message="QR code has expired — please request a fresh certificate.",
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            jwt_kid=jwt_kid, start=start, checks=checks,
            channel=channel, device_fingerprint=device_fingerprint,
            payload_hash=payload_hash,
        )
    except Exception:
        return _log_and_return(
            credential_id=credential_id, credential=None,
            result="token_invalid",
            message="QR token signature is invalid.",
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            jwt_kid=jwt_kid, start=start, checks=checks,
            channel=channel, device_fingerprint=device_fingerprint,
            payload_hash=payload_hash,
        )

    # ── Step 2: sub claim must match URL path ID ──────────────────────────────
    if claims.get("sub") != credential_id:
        return _log_and_return(
            credential_id=credential_id, credential=None,
            result="token_invalid",
            message="Token subject does not match the credential identifier.",
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            jwt_kid=jwt_kid, start=start, checks=checks,
            channel=channel, device_fingerprint=device_fingerprint,
            payload_hash=payload_hash,
        )
    checks.append("sub_claim")

    # ── Step 3: Fetch credential ──────────────────────────────────────────────
    from apps.registry.models import Credential

    try:
        cred = Credential.objects.get(pk=credential_id)
    except (Credential.DoesNotExist, Exception):
        return _log_and_return(
            credential_id=credential_id, credential=None,
            result="not_found",
            message="No credential found for this QR code.",
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            jwt_kid=jwt_kid, start=start, checks=checks,
            channel=channel, device_fingerprint=device_fingerprint,
            payload_hash=payload_hash,
        )

    # ── Step 4: Tamper seal check — MUST precede status checks ────────────────
    # SRS precedence: Tampered > Revoked > Not Found > Invalid
    from apps.registry.canonicaliser import sha256_of_canonical

    computed_hash = sha256_of_canonical(cred.payload)
    if not _hashes_equal(computed_hash, cred.sha256_hash):
        logger.critical(
            "verification.TAMPER_DETECTED credential=%s stored=%s computed=%s",
            cred.id, cred.sha256_hash, computed_hash,
        )
        _raise_tamper_event(cred)
        return _log_and_return(
            credential_id=credential_id, credential=cred,
            result="tampered",
            message="Credential integrity check failed.",
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            jwt_kid=jwt_kid, start=start, checks=checks,
            channel=channel, device_fingerprint=device_fingerprint,
            payload_hash=payload_hash,
        )

    jwt_cred_hash = claims.get("cred_hash", "")
    if jwt_cred_hash and not _hashes_equal(jwt_cred_hash, cred.sha256_hash):
        return _log_and_return(
            credential_id=credential_id, credential=cred,
            result="tampered",
            message="Token hash does not match the registered credential.",
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            jwt_kid=jwt_kid, start=start, checks=checks,
            channel=channel, device_fingerprint=device_fingerprint,
            payload_hash=payload_hash,
        )
    checks.append("tamper_seal")
    if jwt_cred_hash:
        checks.append("cred_hash")

    # ── Step 5: Status / revocation check (AFTER tamper) ─────────────────────
    if cred.status == Credential.STATUS_REVOKED or _is_revoked_cached(str(cred.id)):
        checks.append("revocation_status")
        return _log_and_return(
            credential_id=credential_id, credential=cred,
            result="revoked",
            message="This credential has been revoked.",
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            jwt_kid=jwt_kid, start=start, checks=checks,
            channel=channel, device_fingerprint=device_fingerprint,
            payload_hash=payload_hash,
            extra_data=_revocation_payload(cred),
        )

    if cred.status == Credential.STATUS_QUARANTINED:
        checks.append("revocation_status")
        return _log_and_return(
            credential_id=credential_id, credential=cred,
            result="quarantined",
            message="This credential is currently under review.",
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            jwt_kid=jwt_kid, start=start, checks=checks,
            channel=channel, device_fingerprint=device_fingerprint,
            payload_hash=payload_hash,
        )
    checks.append("revocation_status")

    # ── Step 6: Verified ──────────────────────────────────────────────────────
    elapsed_ms = int((time.monotonic() - start) * 1000)
    if elapsed_ms > 2000:
        logger.warning("verification.slow_response credential=%s ms=%d", credential_id, elapsed_ms)

    return _log_and_return(
        credential_id=credential_id, credential=cred,
        result="verified",
        message="Credential verified successfully.",
        ip=ip, user_agent=user_agent, verifier_id=verifier_id,
        jwt_kid=jwt_kid, start=start, checks=checks,
        channel=channel, device_fingerprint=device_fingerprint,
        payload_hash=payload_hash,
        extra_data=_public_payload(cred),
    )


# ── Private helpers ───────────────────────────────────────────────────────────

def _public_payload(cred) -> dict:
    p = cred.payload
    return {
        "credential_id": str(cred.id),
        "credential_ref": cred.credential_ref,
        "institution_id": str(cred.institution_id),
        "student_full_name": p.get("student_full_name", ""),
        "degree_classification": p.get("degree_classification", ""),
        "programme_code": p.get("programme_code", ""),
        "graduate_index_number": p.get("graduate_index_number", ""),
        "llb_award_date": p.get("llb_award_date", ""),
    }


def _revocation_payload(cred) -> dict:
    """Return revocation detail for a revoked credential response."""
    try:
        from apps.registry.models import RevocationRecord
        record = RevocationRecord.objects.filter(
            credential=cred
        ).order_by("-revoked_at").first()
        if record:
            return {
                "revoked_at": record.revoked_at.isoformat(),
                "reason": record.reason,
                "source": record.source,
            }
    except Exception:
        pass
    return {
        "revoked_at": cred.revoked_at.isoformat() if cred.revoked_at else None,
        "reason": cred.revoke_reason,
        "source": "",
    }


def _log_and_return(
    *, credential_id, credential, result, message,
    ip, user_agent, verifier_id, jwt_kid, start,
    checks, channel, device_fingerprint, payload_hash,
    extra_data=None,
) -> dict:
    elapsed_ms = int((time.monotonic() - start) * 1000)
    result_id_str = None

    try:
        from apps.verification.models import VerificationSession
        session = VerificationSession.objects.create(
            credential_id_claimed=credential_id,
            credential=credential,
            result=result,
            verifier_ip=ip or None,
            verifier_user_agent=user_agent,
            verifier_id=verifier_id,
            jwt_kid=jwt_kid,
            latency_ms=elapsed_ms,
            channel=channel,
            device_fingerprint=device_fingerprint,
            payload_hash=payload_hash,
            checks_performed=checks,
        )
        result_id_str = str(session.result_id)
    except Exception as exc:
        logger.warning("verification.session_log_failed err=%s", exc)

    try:
        from shared.events import publish
        publish(
            "VerificationResultPublished",
            {
                "result": result,
                "credential_id": credential_id,
                "verifier_id": str(verifier_id) if verifier_id else None,
                "ip_address": ip or None,
                "latency_ms": elapsed_ms,
                "result_id": result_id_str,
                "checks_performed": checks,
            },
            topic="evs.audit",
        )
    except Exception as exc:
        logger.warning("verification.audit_publish_failed err=%s", exc)

    response: dict = {
        "result": result,
        "message": message,
        "latency_ms": elapsed_ms,
        "result_id": result_id_str,
    }
    if extra_data:
        if result == "revoked":
            response["revocation"] = extra_data
        else:
            response["credential"] = extra_data
    return response


def _raise_tamper_event(cred):
    try:
        from shared.secops import record_security_event
        record_security_event(
            category="anomaly_detected",
            severity="high",
            indicators={
                "credential_id": str(cred.id),
                "credential_ref": cred.credential_ref,
                "stored_hash": cred.sha256_hash,
            },
        )
    except Exception:
        pass
