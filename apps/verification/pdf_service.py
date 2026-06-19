"""PDF verification service — F06-01 through F06-05.

Pipeline:
  1. Compute file SHA-256 → persist to DocumentVaultObject (content-addressed).
  2. Parse PDF: extract signature blocks, metadata, credential UUID.
  3. For each signature: validate byte-range integrity → walk cert chain →
     check OCSP/CRL revocation → validate embedded timestamp.
  4. Re-compute canonical SHA-256 and compare with registry + embedded cred_hash.
  5. Check revocation status (reuses Phase 3 cache).
  6. Record VerificationSession + PdfSignatureOutcome(s) + AuditEvent.

The parser/PAdES validator integrates with pyhanko (or any PAdES library);
the integration point is _extract_signatures(). Replace the stub with a real
implementation when pyhanko is wired.

Target latency: ≤3000 ms p95.
"""
import hashlib
import logging
import time

from django.utils import timezone

logger = logging.getLogger(__name__)


def verify_pdf(
    *,
    file_bytes: bytes,
    ip: str = "",
    user_agent: str = "",
    verifier_id=None,
) -> dict:
    """Full PDF verification pipeline.

    Returns a result dict with the same vocabulary as verify_credential():
      result: verified | invalid_signature | tampered | revoked | not_found |
              quarantined | untrusted_issuer
      verification_ms: int
      credential: dict (if verified)
      signatures: list[dict]
    """
    start = time.monotonic()

    # ── 1. Compute SHA-256 and persist vault object ────────────────────────────
    file_sha256 = hashlib.sha256(file_bytes).hexdigest()
    _ensure_vault_object(file_sha256, file_bytes, verifier_id)

    # ── 2. Parse PDF signatures ───────────────────────────────────────────────
    try:
        parse_result = _extract_signatures(file_bytes)
    except PdfParseError as exc:
        return _session_and_return(
            channel="pdf",
            result="invalid_signature",
            result_detail=exc.code,
            message=str(exc),
            file_sha256=file_sha256,
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            start=start,
        )

    signatures = parse_result["signatures"]
    raw_metadata = parse_result.get("metadata", {})

    if not signatures:
        return _session_and_return(
            channel="pdf",
            result="invalid_signature",
            result_detail="NO_SIGNATURE_FOUND",
            message="The uploaded PDF does not contain a digital signature.",
            file_sha256=file_sha256,
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            start=start,
        )

    # ── 3. Validate each signature ────────────────────────────────────────────
    sig_outcomes = []
    overall_ok = True
    conflict_detail = ""

    for sig in signatures:
        outcome = _validate_signature(sig)
        sig_outcomes.append(outcome)
        if not (outcome["integrity_ok"] and outcome["chain_ok"] and outcome["revocation_ok"]):
            overall_ok = False
            conflict_detail = outcome.get("failure_reason", "SIGNATURE_VALIDATION_FAILED")

    if not overall_ok:
        session = _session_and_return(
            channel="pdf",
            result="invalid_signature",
            result_detail=conflict_detail,
            message="One or more PDF signatures failed validation.",
            file_sha256=file_sha256,
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            start=start,
        )
        _write_sig_outcomes(session.get("_session_id"), sig_outcomes)
        return session

    # ── 4. Hash comparison ────────────────────────────────────────────────────
    credential_id = raw_metadata.get("credential_id") or raw_metadata.get("sub")
    if not credential_id:
        return _session_and_return(
            channel="pdf",
            result="not_found",
            result_detail="NO_CREDENTIAL_ID_IN_METADATA",
            message="The PDF does not contain a recognisable credential identifier.",
            file_sha256=file_sha256,
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            start=start,
        )

    from apps.registry.models import Credential
    try:
        cred = Credential.objects.get(pk=credential_id)
    except (Credential.DoesNotExist, Exception):
        return _session_and_return(
            channel="pdf",
            result="not_found",
            result_detail="CREDENTIAL_NOT_FOUND",
            message="No credential found for the identifier in this PDF.",
            file_sha256=file_sha256,
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            start=start,
        )

    # Status check
    if cred.status == Credential.STATUS_REVOKED:
        return _session_and_return(
            channel="pdf",
            result="revoked",
            credential=cred,
            message="This credential has been revoked.",
            file_sha256=file_sha256,
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            start=start,
        )
    if cred.status == Credential.STATUS_QUARANTINED:
        return _session_and_return(
            channel="pdf",
            result="quarantined",
            credential=cred,
            message="This credential is under review.",
            file_sha256=file_sha256,
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            start=start,
        )

    # Tamper check (constant-time)
    from apps.registry.canonicaliser import sha256_of_canonical
    computed = sha256_of_canonical(cred.payload)
    stored = cred.sha256_hash
    embedded = raw_metadata.get("cred_hash", "")

    # hmac.compare_digest for constant-time comparison
    import hmac
    hashes_match = hmac.compare_digest(computed, stored)
    if embedded:
        hashes_match = hashes_match and hmac.compare_digest(computed, embedded)

    if not hashes_match:
        session = _session_and_return(
            channel="pdf",
            result="tampered",
            result_detail="HASH_COMPARISON_FAILED",
            credential=cred,
            message="Credential integrity check failed — the document may have been altered.",
            file_sha256=file_sha256,
            ip=ip, user_agent=user_agent, verifier_id=verifier_id,
            start=start,
        )
        _mark_vault_tampered(file_sha256)
        _write_sig_outcomes(session.get("_session_id"), sig_outcomes)
        return session

    # ── 5. Verified ───────────────────────────────────────────────────────────
    session = _session_and_return(
        channel="pdf",
        result="verified",
        credential=cred,
        message="PDF credential verified successfully.",
        file_sha256=file_sha256,
        ip=ip, user_agent=user_agent, verifier_id=verifier_id,
        start=start,
        extra_data=_public_payload(cred),
    )
    _write_sig_outcomes(session.get("_session_id"), sig_outcomes)
    return session


# ── PAdES parser integration point ────────────────────────────────────────────

class PdfParseError(Exception):
    def __init__(self, message, code="MALFORMED_PDF"):
        super().__init__(message)
        self.code = code


def _extract_signatures(file_bytes: bytes) -> dict:
    """Parse PDF and return signature blocks + document metadata.

    Replace this stub with a real pyhanko integration:
      from pyhanko.sign.validation import validate_pdf_signature
      from pyhanko.pdf_utils.reader import PdfFileReader
      ...

    Returns:
      {
        "signatures": [
          {
            "signer_subject": str,
            "signing_time": datetime | None,
            "profile": "pades_bt" | "pades_blt" | "pades_blta" | "pkcs7",
            "byte_range": bytes,  # the signed byte range for integrity check
            "cert_chain": list[bytes],  # DER-encoded certs
            "embedded_timestamp": bytes | None,
          }
        ],
        "metadata": {"credential_id": str, "cred_hash": str, ...},
      }
    """
    if not file_bytes.startswith(b"%PDF"):
        raise PdfParseError("File is not a valid PDF.", "NOT_A_PDF")

    # Stub: in production wire pyhanko here.
    return {"signatures": [], "metadata": {}}


def _validate_signature(sig: dict) -> dict:
    """Validate one signature block.

    In production: walk cert chain against TrustAnchor store, OCSP check,
    timestamp validation. Returns an outcome dict.
    """
    from apps.verification.models import TrustAnchor
    active_cas = list(
        TrustAnchor.objects.filter(status=TrustAnchor.STATUS_ACTIVE)
        .values("id", "ca_name", "ocsp_endpoint", "crl_endpoint")
    )

    # Stub outcome — replace with real pyhanko validation
    return {
        "signer_subject": sig.get("signer_subject", ""),
        "signing_time": sig.get("signing_time"),
        "profile": sig.get("profile", "pkcs7"),
        "integrity_ok": False,
        "chain_ok": False,
        "revocation_ok": False,
        "revocation_status": "unchecked",
        "timestamp_ok": None,
        "signer_ca_id": None,
        "failure_reason": "PADES_PARSER_NOT_WIRED",
    }


# ── Vault helpers ─────────────────────────────────────────────────────────────

def _ensure_vault_object(sha256: str, file_bytes: bytes, uploaded_by):
    """Create DocumentVaultObject if not already stored."""
    from datetime import date, timedelta
    from apps.verification.models import DocumentVaultObject
    DocumentVaultObject.objects.get_or_create(
        sha256=sha256,
        defaults={
            "mime_type": "application/pdf",
            "byte_size": len(file_bytes),
            "uploaded_by": uploaded_by,
            "retention_until": date.today() + timedelta(days=365 * 10),
            "virus_clean": True,  # assume gateway already scanned
        },
    )


def _mark_vault_tampered(sha256: str):
    from apps.verification.models import DocumentVaultObject
    DocumentVaultObject.objects.filter(sha256=sha256).update(tamper_flag=True)


# ── Session + audit helpers ───────────────────────────────────────────────────

def _public_payload(cred) -> dict:
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


def _session_and_return(
    *, channel, result, message,
    ip, user_agent, verifier_id, start,
    file_sha256="", result_detail="", credential=None, extra_data=None,
) -> dict:
    elapsed_ms = int((time.monotonic() - start) * 1000)
    session_id = None

    try:
        from apps.verification.models import VerificationSession
        session = VerificationSession.objects.create(
            channel=channel,
            credential_id_claimed=credential.id if credential else None,
            credential=credential,
            result=result,
            result_detail=result_detail,
            verifier_ip=ip or None,
            verifier_user_agent=user_agent,
            verifier_id=verifier_id,
            file_sha256=file_sha256,
            verification_ms=elapsed_ms,
        )
        session_id = str(session.id)
    except Exception as exc:
        logger.warning("pdf_verify.session_log_failed err=%s", exc)

    try:
        from apps.audit.models import AuditEvent
        AuditEvent.record(
            action="VERIFICATION_RESULT_PUBLISHED",
            entity_type="Credential",
            entity_id=str(credential.id) if credential else file_sha256,
            actor_id=verifier_id,
            ip_address=ip or None,
            new_state={"result": result, "channel": channel, "ms": elapsed_ms, "file_sha256": file_sha256},
            old_state={"result": None},
        )
    except Exception as exc:
        logger.warning("pdf_verify.audit_failed err=%s", exc)

    response = {
        "result": result,
        "result_detail": result_detail,
        "message": message,
        "channel": channel,
        "file_sha256": file_sha256,
        "verification_ms": elapsed_ms,
        "_session_id": session_id,
    }
    if extra_data:
        response["credential"] = extra_data
    return response


def _write_sig_outcomes(session_id: str | None, outcomes: list[dict]):
    if not session_id or not outcomes:
        return
    try:
        from apps.verification.models import PdfSignatureOutcome, VerificationSession
        session = VerificationSession.objects.get(pk=session_id)
        for o in outcomes:
            PdfSignatureOutcome.objects.create(
                verification_session=session,
                signer_subject=o.get("signer_subject", ""),
                signing_time=o.get("signing_time"),
                profile=o.get("profile", "pkcs7"),
                integrity_ok=o.get("integrity_ok", False),
                chain_ok=o.get("chain_ok", False),
                revocation_status=o.get("revocation_status", "unchecked"),
                timestamp_ok=o.get("timestamp_ok"),
                signer_ca_id=o.get("signer_ca_id"),
                failure_reason=o.get("failure_reason", ""),
            )
    except Exception as exc:
        logger.warning("pdf_verify.sig_outcome_write_failed err=%s", exc)
