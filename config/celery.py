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
    # Cleanup security events older than retention window — 04:00 UTC
    "evs-cleanup-security-events": {
        "task": "apps.audit.tasks.cleanup_security_events",
        "schedule": crontab(hour=4, minute=0),
        "options": {"queue": "sla-monitor"},
    },
}
