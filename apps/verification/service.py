"""QR verification service — EVS-F03-01 through EVS-F03-05.

Flow:
  1. Decode and validate the QR JWT signature (HSM JWKS or dev HS256).
  2. Verify the JWT sub claim matches the URL credential_id.
  3. Fetch the credential from the registry.
  4. Check status (active / revoked / quarantined).
  5. Re-compute SHA-256 tamper seal and compare with stored hash + JWT sha claim.
  6. Log a VerificationSession and AuditEvent.
  7. Return a structured result dict — target latency ≤2000 ms.
"""
import logging
import time
import uuid

logger = logging.getLogger(__name__)


def verify_credential(
    *,
    credential_id: str,
    token: str,
    ip: str = "",
    user_agent: str = "",
    verifier_id=None,
) -> dict:
    """Perform a full QR verification and return a structured result dict."""
    start = time.monotonic()

    # ── Step 1: Validate JWT ──────────────────────────────────────────────────
    import jwt as _jwt
    from apps.hsm.service import verify_qr_token

    jwt_kid = ""
    try:
        header = _jwt.get_unverified_header(token)
        jwt_kid = header.get("kid", "")
        claims = verify_qr_token(token)
    except _jwt.ExpiredSignatureError:
        return _log_and_return(
            credential_id=credential_id,
            credential=None,
            result="token_expired",
            message="QR code has expired — please request a fresh certificate.",
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            jwt_kid=jwt_kid, start=start,
        )
    except Exception:
        return _log_and_return(
            credential_id=credential_id,
            credential=None,
            result="token_invalid",
            message="QR token signature is invalid.",
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            jwt_kid=jwt_kid, start=start,
        )

    # ── Step 2: sub claim must match URL path ID ──────────────────────────────
    if claims.get("sub") != credential_id:
        return _log_and_return(
            credential_id=credential_id,
            credential=None,
            result="token_invalid",
            message="Token subject does not match the credential identifier.",
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            jwt_kid=jwt_kid, start=start,
        )

    # ── Step 3: Fetch credential ──────────────────────────────────────────────
    from apps.registry.models import Credential

    try:
        cred = Credential.objects.get(pk=credential_id)
    except (Credential.DoesNotExist, Exception):
        return _log_and_return(
            credential_id=credential_id,
            credential=None,
            result="not_found",
            message="No credential found for this QR code.",
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            jwt_kid=jwt_kid, start=start,
        )

    # ── Step 4: Status check ──────────────────────────────────────────────────
    if cred.status == Credential.STATUS_REVOKED:
        return _log_and_return(
            credential_id=credential_id,
            credential=cred,
            result="revoked",
            message="This credential has been revoked.",
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            jwt_kid=jwt_kid, start=start,
        )

    if cred.status == Credential.STATUS_QUARANTINED:
        return _log_and_return(
            credential_id=credential_id,
            credential=cred,
            result="quarantined",
            message="This credential is currently under review.",
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            jwt_kid=jwt_kid, start=start,
        )

    # ── Step 5: Tamper seal check ─────────────────────────────────────────────
    from apps.registry.canonicaliser import sha256_of_canonical

    computed_hash = sha256_of_canonical(cred.payload)
    if computed_hash != cred.sha256_hash:
        logger.critical(
            "verification.TAMPER_DETECTED credential=%s stored=%s computed=%s",
            cred.id, cred.sha256_hash, computed_hash,
        )
        _raise_tamper_event(cred)
        return _log_and_return(
            credential_id=credential_id,
            credential=cred,
            result="tampered",
            message="Credential integrity check failed.",
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            jwt_kid=jwt_kid, start=start,
        )

    jwt_sha = claims.get("sha", "")
    if jwt_sha and jwt_sha != cred.sha256_hash:
        return _log_and_return(
            credential_id=credential_id,
            credential=cred,
            result="tampered",
            message="Token hash does not match the registered credential.",
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            jwt_kid=jwt_kid, start=start,
        )

    # ── Step 6: Verified ──────────────────────────────────────────────────────
    elapsed_ms = int((time.monotonic() - start) * 1000)
    if elapsed_ms > 2000:
        logger.warning("verification.slow_response credential=%s ms=%d", credential_id, elapsed_ms)

    return _log_and_return(
        credential_id=credential_id,
        credential=cred,
        result="verified",
        message="Credential verified successfully.",
        ip=ip, user_agent=user_agent, verifier_id=verifier_id,
        jwt_kid=jwt_kid, start=start,
        extra_data=_public_payload(cred),
    )


# ── Private helpers ───────────────────────────────────────────────────────────

def _public_payload(cred) -> dict:
    """Fields returned in a successful verification response."""
    p = cred.payload
    return {
        "credential_id": str(cred.id),
        "credential_ref": cred.credential_ref,
        "institution_id": str(cred.institution_id),
        "candidate_name": p.get("candidate_name", ""),
        "programme": p.get("programme", ""),
        "graduation_year": p.get("graduation_year", ""),
        "award_class": p.get("award_class", ""),
    }


def _log_and_return(
    *, credential_id, credential, result, message,
    ip, user_agent, verifier_id, jwt_kid, start,
    extra_data=None,
) -> dict:
    elapsed_ms = int((time.monotonic() - start) * 1000)

    try:
        from apps.verification.models import VerificationSession
        VerificationSession.objects.create(
            credential_id_claimed=credential_id,
            credential=credential,
            result=result,
            verifier_ip=ip or None,
            verifier_user_agent=user_agent,
            verifier_id=verifier_id,
            jwt_kid=jwt_kid,
            verification_ms=elapsed_ms,
        )
    except Exception as exc:
        logger.warning("verification.session_log_failed err=%s", exc)

    try:
        from apps.audit.models import AuditEvent
        AuditEvent.record(
            action="VERIFICATION_RESULT_PUBLISHED",
            entity_type="Credential",
            entity_id=credential_id,
            actor_id=verifier_id,
            ip_address=ip or None,
            new_state={"result": result, "credential_id": credential_id, "ms": elapsed_ms},
            old_state={"result": None},
        )
    except Exception as exc:
        logger.warning("verification.audit_failed err=%s", exc)

    response = {"result": result, "message": message, "verification_ms": elapsed_ms}
    if extra_data:
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
