"""Celery tasks for fraud detection (EVS-F05)."""
from __future__ import annotations

import logging

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)

AUTO_ESCALATION_HOURS = 48


@shared_task(name="evs-fraud-nightly-sweep", bind=True, max_retries=2)
def nightly_fraud_sweep(self):
    """Full-corpus nightly fraud detection run (EVS-F05-01)."""
    from .detection_service import run_detection
    from .models import RuleRun

    try:
        run = run_detection(trigger=RuleRun.TRIGGER_NIGHTLY)
        logger.info(
            "Nightly sweep %s: %d records, %d flags",
            run.id, run.records_scanned, run.flags_created,
        )
        return {"run_id": str(run.id), "flags_created": run.flags_created}
    except Exception as exc:
        logger.exception("Nightly sweep failed: %s", exc)
        raise self.retry(exc=exc, countdown=300)


@shared_task(name="evs-fraud-post-ingest", bind=True, max_retries=3)
def post_ingest_detection(self, batch_id: str):
    """Run detection immediately after a batch is ingested (EVS-F05-01)."""
    from .detection_service import run_detection
    from .models import RuleRun

    try:
        run = run_detection(
            trigger=RuleRun.TRIGGER_POST_INGEST,
            batch_id=batch_id,
        )
        logger.info(
            "Post-ingest sweep for batch %s: %d flags created", batch_id, run.flags_created
        )
        return {"run_id": str(run.id), "flags_created": run.flags_created}
    except Exception as exc:
        logger.exception("Post-ingest detection for batch %s failed: %s", batch_id, exc)
        raise self.retry(exc=exc, countdown=60)


@shared_task(name="evs-fraud-auto-escalation")
def auto_escalate_stale_flags():
    """Escalate HIGH-severity flags that have been open for >48 hours without action (EVS-F05-09)."""
    from .models import FlagAction, FraudFlag

    threshold = timezone.now() - timezone.timedelta(hours=AUTO_ESCALATION_HOURS)
    stale_flags = FraudFlag.objects.filter(
        severity=FraudFlag.SEVERITY_HIGH,
        status=FraudFlag.STATUS_NEW,
        escalated_at__isnull=True,
        created_at__lte=threshold,
    )

    escalated = 0
    for flag in stale_flags:
        try:
            flag.escalated_at = timezone.now()
            flag.save(update_fields=["escalated_at", "updated_at"])
            FlagAction.objects.create(
                flag=flag,
                action=FlagAction.ACTION_ESCALATED,
                payload={
                    "reason": f"Auto-escalated after {AUTO_ESCALATION_HOURS}h without resolution",
                    "severity": flag.severity,
                },
            )
            _notify_escalation(flag)
            escalated += 1
        except Exception as exc:
            logger.exception("Failed to escalate flag %s: %s", flag.id, exc)

    logger.info("Auto-escalation: %d flags escalated", escalated)
    return {"escalated": escalated}


def _notify_escalation(flag) -> None:
    """Send an escalation notification via the notifications app."""
    try:
        from apps.notifications.tasks import dispatch_notification
        dispatch_notification.delay(
            recipient_roles=["registrar", "system_administrator"],
            event_type="fraud_flag_escalated",
            payload={
                "flag_id": str(flag.id),
                "flag_type": flag.flag_type,
                "severity": flag.severity,
                "created_at": flag.created_at.isoformat(),
            },
        )
    except Exception as exc:
        logger.warning("Could not dispatch escalation notification for flag %s: %s", flag.id, exc)
