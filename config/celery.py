"""Celery application and beat schedule for EVS (System 03)."""
import os

from celery import Celery
from celery.schedules import crontab

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.base")

app = Celery("evs")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

app.conf.beat_schedule = {
    # Outbox poller — every 5 seconds
    "evs-outbox-poller": {
        "task": "apps.audit.tasks.poll_outbox",
        "schedule": 5.0,
        "options": {"queue": "outbox"},
    },
    # Daily hash-chain anchor to System 22 — 02:00 UTC (EVS-N02)
    "evs-daily-hash-anchor": {
        "task": "apps.audit.tasks.daily_hash_anchor",
        "schedule": crontab(hour=2, minute=0),
        "options": {"queue": "outbox"},
    },
    # Nightly credential integrity sweep — 03:00 UTC (EVS-N05)
    "evs-integrity-sweep": {
        "task": "apps.registry.tasks.nightly_integrity_sweep",
        "schedule": crontab(hour=3, minute=0),
        "options": {"queue": "integrity-sweep"},
    },
    # SLA monitor — every 15 minutes (graduation cycle deadlines)
    "evs-sla-monitor": {
        "task": "apps.institutions.tasks.sla_monitor",
        "schedule": 60.0 * 15,
        "options": {"queue": "sla-monitor"},
    },
    # Workflow SLA escalation — every 15 minutes (overdue cycles)
    "evs-workflow-sla": {
        "task": "apps.institutions.tasks.workflow_sla_monitor",
        "schedule": 60.0 * 15,
        "options": {"queue": "sla-monitor"},
    },
    # Cleanup security events older than retention window — 04:00 UTC
    "evs-cleanup-security-events": {
        "task": "apps.audit.tasks.cleanup_security_events",
        "schedule": crontab(hour=4, minute=0),
        "options": {"queue": "sla-monitor"},
    },
    # Connector synthetic health probes — every 60 seconds (F04-02)
    "evs-connector-health-probe": {
        "task": "apps.connectors.tasks.synthetic_health_probe",
        "schedule": 60.0,
        "options": {"queue": "sla-monitor"},
    },
    # Manual queue SLA escalation — every 15 minutes
    "evs-queue-sla-escalation": {
        "task": "apps.connectors.tasks.escalate_sla_queue",
        "schedule": 60.0 * 15,
        "options": {"queue": "sla-monitor"},
    },
    # Foreign credential SLA monitor — every 15 minutes
    "evs-fca-sla-monitor": {
        "task": "apps.foreign_credentials.tasks.fca_sla_monitor",
        "schedule": 60.0 * 15,
        "options": {"queue": "sla-monitor"},
    },
}
