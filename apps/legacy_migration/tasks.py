"""Celery tasks for legacy migration (EVS-F09)."""
from __future__ import annotations

import logging

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)

CONFIRMATION_DEADLINE_WARN_HOURS = 48


@shared_task(name="evs-legacy-confirmation-deadline")
def check_confirmation_deadlines():
    """Flag batches approaching or past the 14-day confirmation deadline (EVS-F09-03)."""
    from .models import LegacyBatch, MigrationWave

    now = timezone.now()
    warn_threshold = now + timezone.timedelta(hours=CONFIRMATION_DEADLINE_WARN_HOURS)

    # Waves that are still Active with approaching/past deadlines
    waves_at_risk = MigrationWave.objects.filter(
        status=MigrationWave.STATUS_ACTIVE,
        confirmation_deadline__lte=warn_threshold,
    )

    overdue_count = 0
    warning_count = 0

    for wave in waves_at_risk:
        pending_batches = wave.batches.exclude(
            status__in=[LegacyBatch.STATUS_CONFIRMED, LegacyBatch.STATUS_REJECTED]
        )
        if not pending_batches.exists():
            continue

        if wave.confirmation_deadline <= now:
            # Past deadline — flag for manual review
            _flag_overdue_wave(wave, pending_batches)
            overdue_count += 1
        else:
            # Approaching — send warning notification
            _notify_deadline_approaching(wave, pending_batches)
            warning_count += 1

    logger.info(
        "Confirmation deadline check: %d overdue, %d approaching deadline",
        overdue_count, warning_count,
    )
    return {"overdue": overdue_count, "warnings": warning_count}


def _flag_overdue_wave(wave, pending_batches) -> None:
    """Create an audit event for a wave past its confirmation deadline."""
    try:
        from apps.audit.models import AuditEvent
        batch_refs = list(pending_batches.values_list("batch_ref", flat=True)[:10])
        AuditEvent.record(
            action="LEGACY_CONFIRMATION_DEADLINE_EXCEEDED",
            entity_type="MigrationWave",
            entity_id=str(wave.id),
            actor_id=None,
            new_state={
                "wave_name": wave.name,
                "deadline": wave.confirmation_deadline.isoformat(),
                "unconfirmed_batch_refs": batch_refs,
            },
            old_state={},
        )
        _send_overdue_notification(wave, batch_refs)
    except Exception as exc:
        logger.warning("Failed to flag overdue wave %s: %s", wave.id, exc)


def _notify_deadline_approaching(wave, pending_batches) -> None:
    try:
        batch_refs = list(pending_batches.values_list("batch_ref", flat=True)[:10])
        _send_overdue_notification(wave, batch_refs, approaching=True)
    except Exception as exc:
        logger.warning("Failed to notify approaching deadline for wave %s: %s", wave.id, exc)


def _send_overdue_notification(wave, batch_refs: list, approaching: bool = False) -> None:
    try:
        from apps.notifications.tasks import dispatch_notification
        event_type = (
            "legacy_confirmation_deadline_approaching"
            if approaching
            else "legacy_confirmation_deadline_exceeded"
        )
        dispatch_notification.delay(
            recipient_roles=["registrar", "institution_officer"],
            event_type=event_type,
            payload={
                "wave_id": str(wave.id),
                "wave_name": wave.name,
                "deadline": wave.confirmation_deadline.isoformat(),
                "institution_id": str(wave.institution_id),
                "unconfirmed_batch_refs": batch_refs,
            },
        )
    except Exception as exc:
        logger.warning("Failed to dispatch notification for wave %s: %s", wave.id, exc)
