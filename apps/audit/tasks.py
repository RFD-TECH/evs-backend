"""Audit background tasks: outbox relay, daily hash anchor, cleanup."""
import logging
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)


@shared_task(name="apps.audit.tasks.poll_outbox", queue="outbox")
def poll_outbox():
    """Relay unpublished OutboxEvents to Kafka via System 17 (every 5 s)."""
    from apps.audit.models import OutboxEvent

    batch = list(
        OutboxEvent.objects.filter(published=False)
        .order_by("created_at")[:50]
    )
    if not batch:
        return

    kafka_enabled = getattr(settings, "KAFKA_ENABLED", False)
    published = 0

    for event in batch:
        try:
            if kafka_enabled:
                _publish_to_kafka(event)
            event.published = True
            event.published_at = timezone.now()
            event.save(update_fields=["published", "published_at"])
            published += 1
        except Exception as exc:
            logger.warning("outbox.publish_failed event=%s err=%s", event.correlation_id, exc)

    logger.info("outbox.poll published=%d remaining=%d", published, len(batch) - published)


def _publish_to_kafka(event):
    """Forward OutboxEvent to Kafka via System 17 /v1/events/{topic}."""
    import json
    import requests

    s17_url = getattr(settings, "SYSTEM_17_URL", "")
    if not s17_url:
        return

    from shared.integrations.system17 import get_system17_client
    client = get_system17_client()

    requests.post(
        f"{s17_url}/v1/events/{event.topic}",
        json={
            "event_name": event.event_name,
            "correlation_id": str(event.correlation_id),
            "payload": event.payload,
            "traceparent": event.traceparent,
        },
        headers=client._hmac_headers({"event_name": event.event_name}),
        timeout=5,
    )


@shared_task(name="apps.audit.tasks.daily_hash_anchor", queue="outbox", bind=True)
def daily_hash_anchor(self, target_date: str | None = None):
    """Anchor the previous UTC day's audit chain to System 22."""
    from apps.audit.models import AuditEvent, DailyHashAnchor
    from django.utils import timezone as tz
    from django.db import transaction

    if target_date:
        from datetime import date
        anchor_date = date.fromisoformat(target_date)
    else:
        anchor_date = (tz.now() - timedelta(days=1)).date()

    if DailyHashAnchor.objects.filter(date=anchor_date).exists():
        logger.info("daily_hash_anchor: already anchored date=%s", anchor_date)
        return

    start = tz.datetime(anchor_date.year, anchor_date.month, anchor_date.day, tzinfo=tz.utc)
    end = start + timedelta(days=1)

    events_qs = AuditEvent.objects.filter(created_at__gte=start, created_at__lt=end)
    count = events_qs.count()

    last = events_qs.order_by("-id").values("event_id", "chain_hash").first()

    if last:
        head_event_id = last["event_id"]
        head_hash = last["chain_hash"]
    else:
        prev = AuditEvent.objects.filter(created_at__lt=start).order_by("-id").values("chain_hash").first()
        head_hash = prev["chain_hash"] if prev else "0" * 64
        head_event_id = None

    with transaction.atomic():
        anchor = DailyHashAnchor.objects.create(
            date=anchor_date,
            head_event_id=head_event_id,
            head_hash=head_hash,
            event_count=count,
        )
        from shared.events import publish
        publish(
            "AuditChainAnchorReady",
            {"date": anchor_date.isoformat(), "head_hash": head_hash, "event_count": count},
            topic="evs.audit",
        )

    # Mark as handed off to the relay queue (outbox will deliver to System 22).
    anchor.exported_to_s22_at = tz.now()
    anchor.save(update_fields=["exported_to_s22_at"])

    logger.info("daily_hash_anchor: anchored date=%s events=%d hash=%s", anchor_date, count, head_hash[:12])


@shared_task(name="apps.audit.tasks.cleanup_security_events", queue="sla-monitor")
def cleanup_security_events():
    from apps.audit.models import SecurityEvent
    retention_days = getattr(settings, "EDGE_SECURITY_EVENT_RETENTION_DAYS", 90)
    cutoff = timezone.now() - timedelta(days=retention_days)
    deleted, _ = SecurityEvent.objects.filter(occurred_at__lt=cutoff).delete()
    logger.info("cleanup_security_events: deleted=%d cutoff=%s", deleted, cutoff.date())
