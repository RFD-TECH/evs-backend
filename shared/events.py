"""Transactional outbox for EVS domain events.

publish() writes an OutboxEvent in the same DB transaction as the
domain state change. A Celery task polls every 5 seconds and delivers
unpublished events to Kafka via System 17.
"""
from __future__ import annotations

import threading
import uuid

from django.utils import timezone

_local = threading.local()


def set_request_id(request_id) -> None:
    _local.request_id = request_id


def get_request_id():
    return getattr(_local, "request_id", None)


def set_trace_context(traceparent: str | None, tracestate: str | None) -> None:
    _local.traceparent = traceparent
    _local.tracestate = tracestate


def get_trace_context() -> tuple[str | None, str | None]:
    return getattr(_local, "traceparent", None), getattr(_local, "tracestate", None)


def publish(event_name: str, payload: dict, *, topic: str | None = None) -> None:
    """Write a domain event to the OutboxEvent table (same transaction as caller)."""
    from apps.audit.models import OutboxEvent

    if topic is None:
        topic = _infer_topic(event_name)

    traceparent, tracestate = get_trace_context()

    OutboxEvent.objects.create(
        correlation_id=uuid.uuid4(),
        request_id=get_request_id(),
        traceparent=traceparent,
        tracestate=tracestate,
        topic=topic,
        event_name=event_name,
        payload=payload,
        published=False,
        created_at=timezone.now(),
    )


def _infer_topic(event_name: str) -> str:
    prefix_map = {
        "Credential": "evs.registry",
        "Batch": "evs.registry",
        "Institution": "evs.institutions",
        "Cycle": "evs.institutions",
        "Sla": "evs.institutions",
        "Verification": "evs.verification",
        "Revocation": "evs.verification",
        "Foreign": "evs.foreign",
        "Assessment": "evs.foreign",
        "Equivalence": "evs.foreign",
        "Fraud": "evs.fraud",
        "Flag": "evs.fraud",
        "User": "evs.users",
        "Role": "evs.users",
        "Hsm": "evs.hsm",
        "Waec": "evs.waec",
        "Integrity": "evs.integrity",
        "Audit": "evs.audit",
    }
    for prefix, topic in prefix_map.items():
        if event_name.startswith(prefix):
            return topic
    return "evs.general"
