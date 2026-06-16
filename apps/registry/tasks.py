"""Registry periodic tasks: nightly integrity sweep, batch ingest runner."""
import logging

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)

_SWEEP_BATCH_SIZE = 500


@shared_task(name="apps.registry.tasks.nightly_integrity_sweep", queue="integrity-sweep")
def nightly_integrity_sweep():
    """Recompute SHA-256 for ALL credentials. EVS-N05.

    Records the run in IntegrityRun, anchors the result to System 22 via
    the AuditEvent outbox, and quarantines tampered records.
    """
    from apps.registry.canonicaliser import hashes_equal, sha256_of_canonical
    from apps.registry.models import Credential, IntegrityRun

    run = IntegrityRun.objects.create()

    offset = 0
    tampered = []
    checked = 0

    try:
        while True:
            batch = list(
                Credential.objects.exclude(status=Credential.STATUS_QUARANTINED)
                .order_by("id")[offset: offset + _SWEEP_BATCH_SIZE]
            )
            if not batch:
                break

            for cred in batch:
                expected = sha256_of_canonical(cred.payload)
                ok = hashes_equal(expected, cred.sha256_hash)
                Credential.objects.filter(pk=cred.pk).update(
                    integrity_checked_at=timezone.now(),
                    integrity_ok=ok,
                )
                if not ok:
                    tampered.append(str(cred.id))
                    _handle_tamper(cred, expected)

            checked += len(batch)
            offset += _SWEEP_BATCH_SIZE

        logger.info(
            "nightly_integrity_sweep: checked=%d tampered=%d", checked, len(tampered)
        )

        from apps.audit.models import AuditEvent
        event = AuditEvent.record(
            action="INTEGRITY_SWEEP_COMPLETED",
            entity_type="IntegrityRun",
            entity_id=str(run.id),
            new_state={"checked": checked, "tampered": len(tampered), "tampered_ids": tampered[:20]},
        )
        anchor_hash = event.chain_hash if event else ""

        run.records_checked = checked
        run.tampered_count = len(tampered)
        run.tampered_ids = tampered[:100]
        run.anchor_hash = anchor_hash
        run.status = IntegrityRun.STATUS_COMPLETED
        run.completed_at = timezone.now()
        run.save()

    except Exception as exc:
        run.status = IntegrityRun.STATUS_FAILED
        run.completed_at = timezone.now()
        run.save(update_fields=["status", "completed_at"])
        logger.error("nightly_integrity_sweep: failed err=%s", exc)
        raise


@shared_task(name="apps.registry.tasks.run_batch_ingest", queue="normal")
def run_batch_ingest(*, batch_id: str, file_bytes: bytes):
    """Async runner for a BatchIngest job dispatched by the API."""
    from apps.registry.models import BatchIngest
    from apps.registry.services import process_batch_ingest

    try:
        batch = BatchIngest.objects.get(pk=batch_id)
    except BatchIngest.DoesNotExist:
        logger.error("run_batch_ingest: batch not found id=%s", batch_id)
        return

    try:
        process_batch_ingest(batch, file_bytes)
    except Exception as exc:
        batch.status = BatchIngest.STATUS_FAILED
        batch.row_errors = [{"error": str(exc)}]
        batch.save(update_fields=["status", "row_errors"])
        logger.error("run_batch_ingest: failed id=%s err=%s", batch_id, exc)


def _handle_tamper(cred, computed_hash: str):
    logger.critical(
        "integrity.TAMPER_DETECTED credential_id=%s stored=%s computed=%s",
        cred.id, cred.sha256_hash, computed_hash,
    )
    try:
        from shared.secops import record_security_event
        record_security_event(
            category="anomaly_detected",
            severity="high",
            indicators={
                "credential_id": str(cred.id),
                "credential_ref": cred.credential_ref,
                "stored_hash": cred.sha256_hash,
                "computed_hash": computed_hash,
            },
        )
    except Exception:
        pass

    try:
        from apps.registry.services import quarantine_credential
        quarantine_credential(
            credential=cred,
            actor_id=None,
            reason="Auto-quarantined by nightly integrity sweep — hash mismatch detected.",
        )
    except Exception as exc:
        logger.error("integrity.quarantine_failed credential=%s err=%s", cred.id, exc)
