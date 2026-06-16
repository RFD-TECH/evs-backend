"""Security event recording (best-effort; never raises)."""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def record_security_event(
    *,
    category: str,
    ip_address: str | None = None,
    actor_id: str | None = None,
    request_id=None,
    indicators: dict | None = None,
    severity: str = "warning",
) -> None:
    try:
        from apps.audit.models import SecurityEvent
        event = SecurityEvent.objects.create(
            category=category,
            severity=severity,
            ip_address=ip_address,
            actor_id=actor_id,
            request_id=request_id,
            indicators=indicators or {},
        )
        try:
            from shared.events import publish
            publish(
                "SecurityEventRecorded",
                {
                    "event_id": str(event.event_id),
                    "category": category,
                    "severity": severity,
                    "ip_address": ip_address,
                    "actor_id": str(actor_id) if actor_id else None,
                    "request_id": str(request_id) if request_id else None,
                    "indicators": indicators or {},
                },
                topic="evs.audit",
            )
        except Exception as exc:
            logger.warning("secops.outbox_failed category=%s err=%s", category, exc)
    except Exception as exc:
        logger.warning("secops.record_failed category=%s err=%s", category, exc)
