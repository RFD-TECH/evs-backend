"""MigrationWave state machine service (EVS-F09-01/05)."""
from __future__ import annotations

import logging

from django.db import transaction
from django.utils import timezone

from .models import LegacyBatch, MigrationAuditReport, MigrationWave

logger = logging.getLogger(__name__)


def activate_wave(wave: MigrationWave, *, activated_by) -> MigrationWave:
    """Planned → Active. Only an Administrator may activate a wave."""
    if wave.status != MigrationWave.STATUS_PLANNED:
        raise ValueError(f"Wave must be Planned to activate (current: {wave.status}).")
    wave.status = MigrationWave.STATUS_ACTIVE
    wave.activated_at = timezone.now()
    wave.activated_by = activated_by
    wave.save()
    _audit(wave, "MIGRATION_WAVE_ACTIVATED", activated_by)
    return wave


def promote_to_live(wave: MigrationWave, *, promoted_by) -> MigrationWave:
    """Active → Live.

    Guards:
    1. Wave must have a fully-signed audit report.
    2. All batches in the wave must be Confirmed.
    3. No unconfirmed records remain.
    """
    if wave.status != MigrationWave.STATUS_ACTIVE:
        raise ValueError(f"Wave must be Active to go Live (current: {wave.status}).")

    # Guard 1: dual-signed report
    try:
        report = wave.audit_report
    except MigrationAuditReport.DoesNotExist:
        raise ValueError("Wave cannot go Live without a fully-signed audit report.")
    if not report.is_fully_signed:
        raise ValueError(
            f"Audit report is not fully signed (status: {report.status})."
        )

    # Guard 2 & 3: all batches confirmed
    unconfirmed_batches = wave.batches.exclude(status=LegacyBatch.STATUS_CONFIRMED)
    if unconfirmed_batches.exists():
        refs = list(unconfirmed_batches.values_list("batch_ref", flat=True)[:5])
        raise ValueError(
            f"Not all batches are confirmed. Unconfirmed: {refs}."
        )

    wave.status = MigrationWave.STATUS_LIVE
    wave.went_live_at = timezone.now()
    wave.went_live_by = promoted_by
    wave.save()
    _audit(wave, "MIGRATION_WAVE_WENT_LIVE", promoted_by)
    return wave


def rollback_wave(wave: MigrationWave, *, rolled_back_by, reason: str) -> MigrationWave:
    """Active → RolledBack.

    Rollback does NOT delete credentials. The wave and all its records are preserved.
    Credentials are set to STATUS_SUSPENDED (not revoked) so they can be re-activated
    if the rollback was in error — revoking is a separate deliberate action.
    """
    if wave.status not in (MigrationWave.STATUS_ACTIVE,):
        raise ValueError(f"Only Active waves may be rolled back (current: {wave.status}).")
    if not reason.strip():
        raise ValueError("Rollback reason must not be empty.")

    from apps.registry.models import Credential

    with transaction.atomic():
        wave.status = MigrationWave.STATUS_ROLLED_BACK
        wave.rolled_back_at = timezone.now()
        wave.rolled_back_by = rolled_back_by
        wave.rollback_reason = reason
        wave.save()

        # Suspend (not revoke) all legacy credentials in this wave
        Credential.objects.filter(wave_id=wave.id, status=Credential.STATUS_ACTIVE).update(
            status=Credential.STATUS_SUSPENDED,
        )

    _audit(wave, "MIGRATION_WAVE_ROLLED_BACK", rolled_back_by, {"reason": reason})
    return wave


def quarantine_wave(wave: MigrationWave, *, quarantined_by, reason: str) -> MigrationWave:
    """Live → Quarantined. Compliance hold placed post-go-live."""
    if wave.status != MigrationWave.STATUS_LIVE:
        raise ValueError(f"Only Live waves may be quarantined (current: {wave.status}).")

    from apps.registry.models import Credential

    with transaction.atomic():
        wave.status = MigrationWave.STATUS_QUARANTINED
        wave.quarantined_at = timezone.now()
        wave.quarantine_reason = reason
        wave.save()

        Credential.objects.filter(wave_id=wave.id, status=Credential.STATUS_ACTIVE).update(
            status=Credential.STATUS_SUSPENDED,
        )

    _audit(wave, "MIGRATION_WAVE_QUARANTINED", quarantined_by, {"reason": reason})
    return wave


def _audit(wave: MigrationWave, action: str, actor_id=None, extra: dict | None = None) -> None:
    try:
        from apps.audit.models import AuditEvent
        AuditEvent.record(
            action=action,
            entity_type="MigrationWave",
            entity_id=str(wave.id),
            actor_id=str(actor_id) if actor_id else None,
            new_state={"status": wave.status, **(extra or {})},
            old_state={},
        )
    except Exception as exc:
        logger.warning("Failed to audit wave %s action %s: %s", wave.id, action, exc)
