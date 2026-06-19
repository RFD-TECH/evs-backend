"""Circuit-breaker for external connectors — EVS-F04-02.

State machine: CLOSED → OPEN (on failure threshold) → HALF_OPEN (probing) → CLOSED.

The breaker state is persisted in BreakerState. The current state for a connector
is always the most-recent BreakerState row. State transitions emit an AuditEvent
via the shared outbox.

Thresholds (overridable via connector.latency_p95_threshold_ms):
  error_rate_pct   > 50% over 5-minute rolling window → OPEN
  p95_latency_ms   > connector.latency_p95_threshold_ms over same window → OPEN
  consecutive_ok   ≥ 3 half-open probe successes → CLOSED
"""
import logging
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)

WINDOW_MINUTES = 5
ERROR_RATE_THRESHOLD_PCT = 50.0
HALF_OPEN_OK_REQUIRED = 3


def get_current_state(connector) -> str:
    """Return current breaker state string for this connector."""
    from apps.connectors.models import BreakerState
    latest = BreakerState.objects.filter(connector=connector).order_by("-since").first()
    if latest is None:
        return BreakerState.STATE_CLOSED
    return latest.state


def record_probe(connector, *, ok: bool, latency_ms: int | None = None, error_code: str = ""):
    """Record a synthetic health probe and transition the breaker if thresholds are crossed."""
    from apps.connectors.models import BreakerState, ConnectorHealth

    ConnectorHealth.objects.create(
        connector=connector,
        probe_result=ConnectorHealth.PROBE_OK if ok else ConnectorHealth.PROBE_DOWN,
        latency_ms=latency_ms,
        error_code=error_code,
    )

    current = BreakerState.objects.filter(connector=connector).order_by("-since").first()
    current_state = current.state if current else BreakerState.STATE_CLOSED

    if current_state == BreakerState.STATE_HALF_OPEN:
        _handle_half_open_probe(connector, current, ok)
    elif current_state == BreakerState.STATE_CLOSED:
        _evaluate_closed(connector, current)
    # OPEN state is re-evaluated separately by the periodic half-open probe task


def _evaluate_closed(connector, current_state_row):
    """Check rolling window; open breaker if thresholds crossed."""
    from apps.connectors.models import BreakerState, ConnectorHealth

    window_start = timezone.now() - timedelta(minutes=WINDOW_MINUTES)
    probes = list(
        ConnectorHealth.objects.filter(
            connector=connector, ts__gte=window_start
        ).values_list("probe_result", "latency_ms")
    )
    if len(probes) < 5:
        return  # not enough data

    total = len(probes)
    errors = sum(1 for r, _ in probes if r != ConnectorHealth.PROBE_OK)
    error_rate = (errors / total) * 100

    latencies = [lat for _, lat in probes if lat is not None]
    p95 = sorted(latencies)[int(0.95 * len(latencies))] if latencies else 0

    threshold_exceeded = (
        error_rate > ERROR_RATE_THRESHOLD_PCT
        or p95 > connector.latency_p95_threshold_ms
    )
    if threshold_exceeded:
        BreakerState.objects.create(
            connector=connector,
            state=BreakerState.STATE_OPEN,
            reason=f"error_rate={error_rate:.1f}% p95={p95}ms",
            error_rate_pct=error_rate,
        )
        logger.warning(
            "circuit_breaker.opened connector=%s error_rate=%.1f p95=%d",
            connector.name, error_rate, p95,
        )
        _emit_alert(connector, "CIRCUIT_BREAKER_OPENED", {"error_rate": error_rate, "p95": p95})


def _handle_half_open_probe(connector, state_row, ok: bool):
    """In half-open: count consecutive successes; close or re-open."""
    from apps.connectors.models import BreakerState

    if not ok:
        BreakerState.objects.create(
            connector=connector,
            state=BreakerState.STATE_OPEN,
            reason="Half-open probe failed — re-opening.",
        )
        return

    consecutive = state_row.consecutive_probe_successes + 1
    state_row.consecutive_probe_successes = consecutive
    state_row.save(update_fields=["consecutive_probe_successes"])

    if consecutive >= HALF_OPEN_OK_REQUIRED:
        BreakerState.objects.create(
            connector=connector,
            state=BreakerState.STATE_CLOSED,
            reason=f"{HALF_OPEN_OK_REQUIRED} consecutive half-open probes succeeded.",
        )
        logger.info("circuit_breaker.closed connector=%s", connector.name)
        _emit_alert(connector, "CIRCUIT_BREAKER_CLOSED", {})
        _retry_queued_items(connector)


def enter_half_open(connector):
    """Transition OPEN → HALF_OPEN (called by the periodic task after a backoff)."""
    from apps.connectors.models import BreakerState
    current_state = get_current_state(connector)
    if current_state != BreakerState.STATE_OPEN:
        return
    BreakerState.objects.create(
        connector=connector,
        state=BreakerState.STATE_HALF_OPEN,
        reason="Attempting recovery probe.",
    )


def is_open(connector) -> bool:
    from apps.connectors.models import BreakerState
    return get_current_state(connector) == BreakerState.STATE_OPEN


def _emit_alert(connector, action: str, payload: dict):
    try:
        from apps.audit.models import AuditEvent
        AuditEvent.record(
            action=action,
            entity_type="Connector",
            entity_id=str(connector.id),
            new_state={"connector": connector.name, **payload},
            old_state={},
        )
    except Exception as exc:
        logger.warning("circuit_breaker.alert_failed err=%s", exc)


def _retry_queued_items(connector):
    """Trigger async retry of pending manual queue items when breaker closes."""
    try:
        from apps.connectors.tasks import retry_connector_queue
        retry_connector_queue.delay(str(connector.id))
    except Exception as exc:
        logger.warning("circuit_breaker.retry_trigger_failed err=%s", exc)
