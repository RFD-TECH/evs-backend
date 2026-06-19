"""Foreign Credential Assessment periodic tasks — SLA monitoring."""
import logging

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)


@shared_task(name="apps.foreign_credentials.tasks.fca_sla_monitor", queue="sla-monitor")
def fca_sla_monitor():
    """Flag applications where per-stage SLA has been breached."""
    from apps.foreign_credentials.models import ForeignCredentialApplication, FcaSlaEvent

    active_stages = [
        ForeignCredentialApplication.STAGE_SUBMITTED,
        ForeignCredentialApplication.STAGE_TRIAGED,
        ForeignCredentialApplication.STAGE_ROUTED_INTERNAL,
        ForeignCredentialApplication.STAGE_ROUTED_GTEC,
        ForeignCredentialApplication.STAGE_ASSESSOR_ASSIGNED,
        ForeignCredentialApplication.STAGE_UNDER_REVIEW,
        ForeignCredentialApplication.STAGE_RECOMMENDATION_MADE,
        ForeignCredentialApplication.STAGE_REGISTRAR_REVIEWED,
        ForeignCredentialApplication.STAGE_DG_PENDING,
    ]

    overdue = ForeignCredentialApplication.objects.filter(
        stage__in=active_stages,
        sla_due_at__lt=timezone.now(),
    )
    for app in overdue:
        already_breached = FcaSlaEvent.objects.filter(
            application=app,
            stage=app.stage,
            event="breached",
        ).exists()
        if already_breached:
            continue

        FcaSlaEvent.objects.create(
            application=app,
            stage=app.stage,
            event="breached",
            sla_due_at=app.sla_due_at,
        )
        logger.warning("fca.sla_breached app=%s stage=%s", app.reference, app.stage)

        try:
            from apps.audit.models import AuditEvent
            AuditEvent.record(
                action="FCA_SLA_BREACHED",
                entity_type="ForeignCredentialApplication",
                entity_id=str(app.id),
                new_state={"stage": app.stage, "reference": app.reference},
                old_state={},
            )
        except Exception:
            pass
