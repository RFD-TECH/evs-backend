"""Users periodic tasks.

Role lifecycle (grant, revoke, expiry) is managed by IAM (System 19).
EVS retains only the session-cleanup placeholder for future use.
"""
import logging

from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(name="apps.users.tasks.expire_stale_sessions", queue="normal")
def expire_stale_sessions():
    """Placeholder — session management is handled by IAM / Keycloak."""
    pass
