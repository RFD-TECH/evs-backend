"""WAEC API integration — EVS-F08.

Implements the verification call with:
  - Circuit-breaker check before every call.
  - Exponential backoff on transient errors (5xx, 429, timeout).
  - Response mapping → standard verification vocabulary.
  - PII sanitisation (DOB masked, only permitted fields retained).
  - Manual queue fallback when breaker is open.

Target round-trip: ≤5000 ms p95.
"""
import hashlib
import hmac
import json
import logging
import time
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
BACKOFF_BASE_S = 0.5
REQUEST_TIMEOUT_S = 8.0

# WAEC response → EVS vocabulary
WAEC_RESPONSE_MAP = {
    "VERIFIED": "verified",
    "MATCH": "verified",
    "NOT_FOUND": "not_found",
    "MISMATCH": "mismatch",
    "RECORD_NOT_FOUND": "not_found",
}


def verify_waec(
    *,
    index_number: str,
    year_of_completion: int,
    examination_series: str,
    date_of_birth: str,  # DD/MM/YYYY — masked before storage
    verifier_id=None,
    ip: str = "",
) -> dict:
    """Run a WAEC verification.

    Returns:
      result: verified | not_found | mismatch | api_error | manual_pending
      message: str
      verification_ms: int
      data: dict (name, subjects, grades — only when verified and permitted)
      queue_ref: str | None (when manual_pending)
    """
    start = time.monotonic()

    connector = _get_waec_connector()
    if connector is None:
        return {
            "result": "api_error",
            "message": "WAEC connector not configured.",
            "verification_ms": 0,
        }

    # Breaker check
    from apps.connectors.circuit_breaker import is_open
    if is_open(connector):
        queue_id = _enqueue_manual(
            connector, index_number, year_of_completion, examination_series, date_of_birth, verifier_id
        )
        return {
            "result": "manual_pending",
            "message": "WAEC is temporarily unavailable. Your request has been queued for manual verification.",
            "queue_ref": queue_id,
            "verification_ms": int((time.monotonic() - start) * 1000),
        }

    # Build request payload
    dob_masked = _mask_dob(date_of_birth)
    payload_raw = json.dumps({
        "index_number": index_number,
        "year_of_completion": year_of_completion,
        "examination_series": examination_series,
        "date_of_birth": date_of_birth,
    }, sort_keys=True)
    payload_hash = hashlib.sha256(payload_raw.encode()).hexdigest()

    # Call WAEC API with retry/backoff
    response_status, sanitised_response, latency_ms, error = _call_waec(
        connector, payload_raw, start
    )

    from apps.connectors.models import WaecRequest
    waec_req = WaecRequest.objects.create(
        index_number=index_number,
        year_of_completion=year_of_completion,
        examination_series=examination_series,
        dob_masked=dob_masked,
        request_payload_hash=payload_hash,
        response_status=response_status or "api_error",
        sanitised_response=sanitised_response,
        latency_ms=latency_ms,
        queued_flag=False,
    )

    # Log VerificationSession
    _write_session(
        result=response_status or "api_error",
        verifier_id=verifier_id,
        ip=ip,
        latency_ms=latency_ms,
        waec_req_id=str(waec_req.id),
    )

    if error:
        return {
            "result": "api_error",
            "message": "WAEC verification service returned an error. Please try again.",
            "verification_ms": latency_ms or 0,
        }

    message = {
        "verified": "Verified – Matches Official Record",
        "not_found": "No matching record found in WAEC.",
        "mismatch": "Details provided do not match the official WAEC record.",
        "api_error": "WAEC verification service error.",
    }.get(response_status, "Verification complete.")

    return {
        "result": response_status,
        "message": message,
        "verification_ms": latency_ms or 0,
        "data": sanitised_response if response_status == "verified" else None,
    }


def _get_waec_connector():
    from apps.connectors.models import Connector
    return Connector.objects.filter(kind=Connector.KIND_WAEC, lifecycle_state=Connector.LIFECYCLE_LIVE).first()


def _call_waec(connector, payload_raw: str, start) -> tuple:
    """HTTP call to WAEC with retry/backoff. Returns (status, sanitised_response, latency_ms, error)."""
    import requests
    from django.conf import settings

    endpoint = connector.active_endpoint
    for attempt in range(MAX_RETRIES):
        t0 = time.monotonic()
        try:
            resp = requests.post(
                endpoint,
                data=payload_raw,
                headers={
                    "Content-Type": "application/json",
                    "X-Correlation-Id": _new_correlation_id(),
                    "Authorization": f"Bearer {_get_access_token(connector)}",
                },
                timeout=REQUEST_TIMEOUT_S,
            )
            latency_ms = int((time.monotonic() - t0) * 1000)
        except requests.Timeout:
            _backoff(attempt)
            continue
        except requests.RequestException as exc:
            logger.warning("waec.request_error attempt=%d err=%s", attempt, exc)
            _backoff(attempt)
            continue

        if resp.status_code in (429, 500, 502, 503, 504):
            _backoff(attempt)
            continue

        if resp.status_code != 200:
            return "api_error", None, int((time.monotonic() - t0) * 1000), True

        try:
            body = resp.json()
        except Exception:
            return "api_error", None, latency_ms, True

        raw_status = (body.get("status") or body.get("result") or "").upper()
        evs_status = WAEC_RESPONSE_MAP.get(raw_status, "api_error")
        sanitised = _sanitise_response(body, evs_status)
        return evs_status, sanitised, latency_ms, False

    # All retries exhausted
    return "api_error", None, int((time.monotonic() - start) * 1000), True


def _sanitise_response(body: dict, status: str) -> dict:
    """Keep only fields permitted by the WAEC data-sharing agreement."""
    if status != "verified":
        return {"status": status}
    return {
        "status": status,
        "candidate_name": body.get("candidateName") or body.get("candidate_name", ""),
        "subjects": body.get("subjects", []),
        "grades": body.get("grades", {}),
    }


def _mask_dob(dob: str) -> str:
    """DD/MM/YYYY → MM/***** for PII-safe storage."""
    parts = dob.split("/")
    if len(parts) == 3:
        return f"{parts[1]}/*****"
    return "*****"


def _enqueue_manual(connector, index_number, year, series, dob, verifier_id) -> str:
    from apps.connectors.models import ManualQueueItem
    item = ManualQueueItem.objects.create(
        connector=connector,
        original_payload={
            "index_number": index_number,
            "year_of_completion": year,
            "examination_series": series,
            "dob_masked": _mask_dob(dob),
        },
        consumer_id="direct",
        sla_due_at=timezone.now() + timedelta(hours=24),
    )
    return str(item.id)


def _write_session(*, result, verifier_id, ip, latency_ms, waec_req_id):
    try:
        from apps.verification.models import VerificationSession
        VerificationSession.objects.create(
            channel=VerificationSession.CHANNEL_WAEC,
            result=result,
            verifier_ip=ip or None,
            verifier_id=verifier_id,
            verification_ms=latency_ms,
        )
    except Exception as exc:
        logger.warning("waec.session_log_failed err=%s", exc)


def _new_correlation_id() -> str:
    import uuid
    return str(uuid.uuid4())


def _get_access_token(connector) -> str:
    # TODO: implement OAuth token fetch via ConnectorCredential + HSM decryption
    return ""


def _backoff(attempt: int):
    import time as _time
    _time.sleep(BACKOFF_BASE_S * (2 ** attempt))
