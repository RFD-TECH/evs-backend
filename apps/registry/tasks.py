"""Registry periodic tasks: nightly integrity sweep (Phase 9 hardened), batch ingest runner."""
import base64
import hashlib
import logging

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)

_SWEEP_BATCH_SIZE = 500


@shared_task(
    name="apps.registry.tasks.nightly_integrity_sweep",
    queue="integrity-sweep",
    bind=True,
    max_retries=0,
)
def nightly_integrity_sweep(self, *, sweep_type: str = "scheduled", triggered_by: str | None = None):
    """Recompute SHA-256 for 100% of active credentials. EVS-N05 (Phase 9 hardened).

    Improvements over the pre-Phase-9 version
    ------------------------------------------
    - Creates an ``IntegrityRun`` record at start, updating it live.
    - Resumes from ``checkpoint_state`` if a prior ``running`` run exists
      (crash recovery — avoids re-checking already-verified credentials).
    - After the full sweep, computes a SHA-256 Merkle root over all
      ``"{uuid}:{sha256_hash}"`` pairs sorted by credential UUID.
    - HSM-signs the Merkle root and stores it in ``IntegrityRun``.
    - Clears the Redis verification cache for any quarantined credential.
    """
    from apps.registry.canonicaliser import sha256_of_canonical
    from apps.registry.models import Credential, IntegrityRun

    # ── Crash recovery: resume an existing running run ────────────────────────
    run = (
        IntegrityRun.objects.filter(status=IntegrityRun.STATUS_RUNNING)
        .order_by("started_at")
        .first()
    )
    if run:
        logger.info(
            "nightly_integrity_sweep: resuming run=%s from checkpoint=%s",
            run.id,
            run.checkpoint_state,
        )
        last_id = run.checkpoint_state.get("last_id")
        checked = run.checkpoint_state.get("checked", 0)
        tampered_list: list[str] = run.checkpoint_state.get("tampered_ids", [])
    else:
        run = IntegrityRun.objects.create(
            sweep_type=sweep_type,
            triggered_by=triggered_by,
            status=IntegrityRun.STATUS_RUNNING,
        )
        last_id = None
        checked = 0
        tampered_list = []

    # ── Pair list for Merkle computation: (str(uuid), sha256_hash) ────────────
    # Loaded from checkpoint so we can continue accumulating across restarts.
    merkle_pairs: list[str] = run.checkpoint_state.get("merkle_pairs", [])

    try:
        qs = Credential.objects.filter(status=Credential.STATUS_ACTIVE).order_by("id")
        if last_id:
            qs = qs.filter(id__gt=last_id)

        offset = 0
        while True:
            batch = list(qs[offset: offset + _SWEEP_BATCH_SIZE])
            if not batch:
                break

            for cred in batch:
                expected = sha256_of_canonical(cred.payload)
                ok = expected == cred.sha256_hash
                Credential.objects.filter(pk=cred.pk).update(
                    integrity_checked_at=timezone.now(),
                    integrity_ok=ok,
                )
                merkle_pairs.append(f"{cred.id}:{cred.sha256_hash}")

                if not ok:
                    tampered_list.append(str(cred.id))
                    _handle_tamper(cred, expected)
                    _clear_verification_cache(str(cred.id))

            checked += len(batch)
            last_checked_id = str(batch[-1].id)
            offset += _SWEEP_BATCH_SIZE

            # Save checkpoint after every batch so crash recovery is granular.
            IntegrityRun.objects.filter(pk=run.pk).update(
                total_checked=checked,
                tampered_count=len(tampered_list),
                checkpoint_state={
                    "last_id": last_checked_id,
                    "checked": checked,
                    "tampered_ids": tampered_list[:100],   # cap stored list
                    "merkle_pairs": merkle_pairs,
                },
            )

    except Exception as exc:
        IntegrityRun.objects.filter(pk=run.pk).update(
            status=IntegrityRun.STATUS_FAILED,
            error_detail=str(exc),
            completed_at=timezone.now(),
        )
        logger.critical("nightly_integrity_sweep: FAILED run=%s err=%s", run.id, exc)
        raise

    # ── Compute Merkle root ───────────────────────────────────────────────────
    merkle_root = _compute_merkle_root(merkle_pairs)

    # ── HSM-sign Merkle root ──────────────────────────────────────────────────
    hsm_sig, hsm_key_id = _sign_merkle_root(merkle_root)

    # ── Finalise IntegrityRun ─────────────────────────────────────────────────
    IntegrityRun.objects.filter(pk=run.pk).update(
        status=IntegrityRun.STATUS_COMPLETED,
        total_checked=checked,
        tampered_count=len(tampered_list),
        merkle_root=merkle_root,
        hsm_signature=hsm_sig,
        hsm_key_id=hsm_key_id,
        completed_at=timezone.now(),
        checkpoint_state={},   # clear checkpoint once done
    )

    logger.info(
        "nightly_integrity_sweep: run=%s checked=%d tampered=%d merkle_root=%s",
        run.id, checked, len(tampered_list), merkle_root[:12],
    )

    from apps.audit.models import AuditEvent
    AuditEvent.record(
        action="INTEGRITY_SWEEP_COMPLETED",
        entity_type="IntegrityRun",
        entity_id=str(run.id),
        new_state={
            "checked": checked,
            "tampered": len(tampered_list),
            "tampered_ids": tampered_list[:20],
            "merkle_root": merkle_root,
        },
    )

    return str(run.id)


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


# ── Internal helpers ──────────────────────────────────────────────────────────

def _compute_merkle_root(pairs: list[str]) -> str:
    """SHA-256 of all '{uuid}:{sha256}' pairs sorted lexicographically."""
    joined = "\n".join(sorted(pairs))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _sign_merkle_root(merkle_root: str) -> tuple[str, str]:
    """Return (base64_signature, key_id) for the Merkle root."""
    from django.conf import settings
    import hmac as hmac_lib

    if getattr(settings, "HSM_ENABLED", False):
        try:
            from apps.hsm.service import get_hsm_service
            hsm = get_hsm_service()
            key_id = getattr(settings, "HSM_KEY_ID_CREDENTIAL_SIGN", "evs-cred-sign-v1")
            sig_bytes = hsm.sign(key_id=key_id, data=merkle_root.encode())
            return base64.b64encode(sig_bytes).decode(), key_id
        except Exception as exc:
            logger.warning("integrity_sweep.hsm_sign_failed — HMAC fallback: %s", exc)

    secret = settings.SECRET_KEY.encode()
    sig = hmac_lib.new(secret, merkle_root.encode(), hashlib.sha256).digest()
    return base64.b64encode(sig).decode(), "software-hmac-sha256"


def _clear_verification_cache(credential_id: str) -> None:
    """Invalidate cached verification results for a quarantined credential."""
    try:
        from django.core.cache import cache
        cache.delete(f"evs:verify:{credential_id}")
        cache.delete(f"evs:qr:{credential_id}")
    except Exception as exc:
        logger.warning("integrity_sweep.cache_clear_failed credential=%s err=%s", credential_id, exc)


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
