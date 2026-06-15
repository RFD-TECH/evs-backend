"""Institution SLA monitoring tasks."""
import logging
from datetime import date

from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(name="apps.institutions.tasks.sla_monitor", queue="sla-monitor")
def sla_monitor():
    """Check open graduation cycles and emit SLA events / notifications.

    Triggers:
      - D-20 reminder: 20 or fewer days remaining before deadline
      - D-7 reminder: 7 or fewer days remaining before deadline
      - Overdue escalation: deadline has passed and cycle is still open
    """
    from apps.institutions.models import GraduationCycle, SlaEvent

    today = date.today()
    open_cycles = GraduationCycle.objects.filter(
        status__in=[GraduationCycle.STATUS_OPEN]
    ).select_related("institution")

    d20_count = d7_count = overdue_count = 0

    for cycle in open_cycles:
        days_remaining = (cycle.submission_deadline - today).days

        if days_remaining < 0:
            # Past deadline — escalate to overdue
            cycle.status = GraduationCycle.STATUS_OVERDUE
            cycle.save(update_fields=["status", "updated_at"])
            SlaEvent.objects.create(
                cycle=cycle,
                event_type=SlaEvent.EVENT_OVERDUE_ESCALATION,
                details={
                    "deadline": cycle.submission_deadline.isoformat(),
                    "days_overdue": abs(days_remaining),
                    "institution": cycle.institution.code,
                },
            )
            _notify_sla(cycle, "overdue_escalation", days_remaining)
            overdue_count += 1
            continue

        if days_remaining <= 7 and not cycle.sla_d7_notified:
            SlaEvent.objects.create(
                cycle=cycle,
                event_type=SlaEvent.EVENT_D7_REMINDER,
                details={
                    "days_remaining": days_remaining,
                    "deadline": cycle.submission_deadline.isoformat(),
                    "institution": cycle.institution.code,
                },
            )
            cycle.sla_d7_notified = True
            cycle.save(update_fields=["sla_d7_notified", "updated_at"])
            _notify_sla(cycle, "d7_reminder", days_remaining)
            d7_count += 1

        elif days_remaining <= 20 and not cycle.sla_d20_notified:
            SlaEvent.objects.create(
                cycle=cycle,
                event_type=SlaEvent.EVENT_D20_REMINDER,
                details={
                    "days_remaining": days_remaining,
                    "deadline": cycle.submission_deadline.isoformat(),
                    "institution": cycle.institution.code,
                },
            )
            cycle.sla_d20_notified = True
            cycle.save(update_fields=["sla_d20_notified", "updated_at"])
            _notify_sla(cycle, "d20_reminder", days_remaining)
            d20_count += 1

    logger.info(
        "sla_monitor: d20=%d d7=%d overdue=%d",
        d20_count, d7_count, overdue_count,
    )


@shared_task(name="apps.institutions.tasks.workflow_sla_monitor", queue="sla-monitor")
def workflow_sla_monitor():
    """Check overdue cycles for escalation to CLET management. Runs every 15 min."""
    from apps.institutions.models import GraduationCycle

    overdue = GraduationCycle.objects.filter(status=GraduationCycle.STATUS_OVERDUE)
    for cycle in overdue:
        days_overdue = (date.today() - cycle.submission_deadline).days
        if days_overdue > 3:
            # Publish escalation event for System 21 (notifications)
            from shared.events import publish
            publish(
                "SlaEscalationRequired",
                {
                    "cycle_id": str(cycle.id),
                    "institution": cycle.institution.code,
                    "days_overdue": days_overdue,
                    "deadline": cycle.submission_deadline.isoformat(),
                },
                topic="evs.sla",
            )


def _notify_sla(cycle, event_type: str, days_remaining: int):
    """Publish notification event to System 21 via outbox."""
    try:
        from shared.events import publish
        publish(
            "SlaReminderTriggered",
            {
                "event_type": event_type,
                "cycle_id": str(cycle.id),
                "institution_id": str(cycle.institution.id),
                "institution_code": cycle.institution.code,
                "days_remaining": days_remaining,
                "deadline": cycle.submission_deadline.isoformat(),
            },
            topic="evs.notifications",
        )
    except Exception as exc:
        logger.warning("sla.notify_failed cycle=%s err=%s", cycle.id, exc)
