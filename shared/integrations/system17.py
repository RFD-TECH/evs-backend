"""System 17 (API Layer) client for EVS.

Used to:
- Relay audit events to CALS (System 22) via S17's /v1/relay/audit endpoint.
- Forward domain events to the Kafka bus.
- Call NLEMS eligibility endpoint.
- Call NBES registration gate.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import uuid
from datetime import UTC, datetime
from functools import lru_cache

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

_GENESIS_HASH = "0" * 64


class System17Client:
    def __init__(self):
        self._base_url = (getattr(settings, "SYSTEM_17_URL", "") or "").rstrip("/")
        self._secret = getattr(settings, "SYSTEM_17_HMAC_SECRET", "") or ""
        self._timeout = getattr(settings, "SYSTEM_17_TIMEOUT_SECONDS", 5.0)
        self._enabled = bool(self._base_url and self._secret)

    def relay_audit_event(
        self,
        *,
        action: str,
        resource_type: str,
        resource_id: str,
        user_id: str,
        principal: str,
        previous_hash: str = _GENESIS_HASH,
        current_hash: str = "",
        sequence: int = 1,
        trace_id: str = "",
        span_id: str = "",
        payload: dict | None = None,
    ) -> bool:
        if not self._enabled:
            return True

        body = {
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "serviceName": "system-03-evs",
            "action": action,
            "resourceType": resource_type,
            "resourceId": str(resource_id),
            "userId": str(user_id),
            "principal": str(principal) or "system",
            "previousHash": previous_hash,
            "currentHash": current_hash,
            "sequence": sequence,
            "traceId": trace_id or uuid.uuid4().hex,
            "spanId": span_id or uuid.uuid4().hex[:16],
            "schemaVersion": "1",
        }
        if payload:
            body["payload"] = payload

        try:
            resp = requests.post(
                f"{self._base_url}/v1/relay/audit",
                json=body,
                headers=self._hmac_headers(body),
                timeout=self._timeout,
            )
            return resp.status_code in (200, 201, 202)
        except Exception as exc:
            logger.warning("system17.relay_audit.error action=%s err=%s", action, exc)
            return False

    def _hmac_headers(self, body: dict) -> dict:
        import json
        ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        nonce = secrets.token_hex(16)
        body_bytes = json.dumps(body, separators=(",", ":")).encode()
        sig = hmac.new(
            self._secret.encode(),
            f"{ts}{nonce}".encode() + body_bytes,
            hashlib.sha256,
        ).hexdigest()
        return {
            "X-Timestamp": ts,
            "X-Nonce": nonce,
            "X-Signature": sig,
            "X-Idempotency-Key": f"evs-audit-{uuid.uuid4().hex}",
        }


@lru_cache(maxsize=1)
def get_system17_client() -> System17Client:
    return System17Client()
