"""Connector periodic tasks — health probes, breaker half-open, SLA escalation."""
import logging
from datetime import timedelta

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)


@shared_task(name="apps.connectors.tasks.synthetic_health_probe", queue="sla-monitor")
def synthetic_health_probe():
    """Probe all live connectors every 60 seconds (F04-02)."""
    from apps.connectors.models import Connector, ConnectorHealth
    from apps.connectors.circuit_breaker import record_probe, enter_half_open, get_current_state

    live = Connector.objects.filter(
        lifecycle_state__in=[Connector.LIFECYCLE_LIVE, Connector.LIFECYCLE_SANDBOX]
    )
    for connector in live:
        try:
            ok, latency_ms = _probe_connector(connector)
            record_probe(connector, ok=ok, latency_ms=latency_ms)
        except Exception as exc:
            logger.warning("health_probe.failed connector=%s err=%s", connector.name, exc)
            record_probe(connector, ok=False, error_code=str(exc)[:50])

        # Attempt half-open transition for open breakers
        from apps.connectors.models import BreakerState
        if get_current_state(connector) == BreakerState.STATE_OPEN:
            enter_half_open(connector)


@shared_task(name="apps.connectors.tasks.escalate_sla_queue", queue="sla-monitor")
def escalate_sla_queue():
    """Escalate manual queue items past SLA due date (F04-04)."""
    from apps.connectors.models import ManualQueueItem

    overdue = ManualQueueItem.objects.filter(
        status__in=[ManualQueueItem.STATUS_PENDING, ManualQueueItem.STATUS_CLAIMED],
        sla_due_at__lt=timezone.now(),
    )
    for item in overdue:
        item.status = ManualQueueItem.STATUS_ESCALATED
        item.save(update_fields=["status"])
        logger.info("queue.escalated item=%s", item.id)
        try:
            from apps.audit.models import AuditEvent
            AuditEvent.record(
                action="MANUAL_QUEUE_SLA_ESCALATED",
                entity_type="ManualQueueItem",
                entity_id=str(item.id),
                new_state={"status": "escalated", "connector": item.connector.name if item.connector else ""},
                old_state={"status": "pending"},
            )
        except Exception:
            pass


@shared_task(name="apps.connectors.tasks.retry_connector_queue", queue="sla-monitor")
def retry_connector_queue(connector_id: str):
    """Re-attempt pending manual queue items when breaker closes (F08-03)."""
    from apps.connectors.models import Connector, ManualQueueItem

    try:
        connector = Connector.objects.get(pk=connector_id)
    except Connector.DoesNotExist:
        return

    pending = ManualQueueItem.objects.filter(
        connector=connector,
        status=ManualQueueItem.STATUS_PENDING,
    )
    for item in pending:
        logger.info("queue.auto_retry item=%s connector=%s", item.id, connector.name)
        # Re-send the original payload — connector-specific dispatch
        _dispatch_retry(connector, item)


def _probe_connector(connector) -> tuple:
    """Simple HTTP GET to the connector's health endpoint."""
    import time
    import requests

    endpoint = connector.active_endpoint
    if not endpoint:
        return False, None

    probe_url = endpoint.rstrip("/") + "/health"
    t0 = time.monotonic()
    try:
        resp = requests.get(probe_url, timeout=5)
        latency_ms = int((time.monotonic() - t0) * 1000)
        return resp.status_code < 400, latency_ms
    except requests.RequestException:
        latency_ms = int((time.monotonic() - t0) * 1000)
        return False, latency_ms


def _dispatch_retry(connector, item):
    """Re-dispatch a manual queue item through the connector."""
    if connector.kind == "waec":
        _retry_waec(connector, item)


def _retry_waec(connector, item):
    payload = item.original_payload
    try:
        from apps.connectors.waec_service import verify_waec
        result = verify_waec(
            index_number=payload.get("index_number", ""),
            year_of_completion=payload.get("year_of_completion", 0),
            examination_series=payload.get("examination_series", ""),
            date_of_birth="**/**/**",  # DOB masked; WAEC retry uses stored index
        )
        if result["result"] not in ("api_error", "manual_pending"):
            item.status = "resolved"
            item.resolved_at = timezone.now()
            item.resolution_status = result["result"]
            item.save(update_fields=["status", "resolved_at", "resolution_status"])
    except Exception as exc:
        logger.warning("queue.retry_failed item=%s err=%s", item.id, exc)
