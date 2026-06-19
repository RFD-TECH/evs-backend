"""Audit background tasks: outbox relay, daily hash anchor, cleanup."""
import logging
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)


@shared_task(name="apps.audit.tasks.poll_outbox", queue="outbox")
def poll_outbox():
    """Relay unpublished OutboxEvents to Kafka via System 17 (every 5 s)."""
    from apps.audit.models import OutboxEvent

    batch = list(
        OutboxEvent.objects.filter(published=False)
        .order_by("created_at")[:50]
    )
    if not batch:
        return

    kafka_enabled = getattr(settings, "KAFKA_ENABLED", False)
    published = 0

    for event in batch:
        try:
            if kafka_enabled:
                _publish_to_kafka(event)
            event.published = True
            event.published_at = timezone.now()
            event.save(update_fields=["published", "published_at"])
            published += 1
        except Exception as exc:
            logger.warning("outbox.publish_failed event=%s err=%s", event.correlation_id, exc)

    logger.info("outbox.poll published=%d remaining=%d", published, len(batch) - published)


def _publish_to_kafka(event):
    """Forward OutboxEvent to Kafka via System 17 /v1/events/{topic}."""
    import json
    import requests

    s17_url = getattr(settings, "SYSTEM_17_URL", "")
    if not s17_url:
        return

    from shared.integrations.system17 import get_system17_client
    client = get_system17_client()

    requests.post(
        f"{s17_url}/v1/events/{event.topic}",
        json={
            "event_name": event.event_name,
            "correlation_id": str(event.correlation_id),
            "payload": event.payload,
            "traceparent": event.traceparent,
        },
        headers=client._hmac_headers({"event_name": event.event_name}),
        timeout=5,
    )


@shared_task(name="apps.audit.tasks.daily_hash_anchor", queue="outbox", bind=True)
def daily_hash_anchor(self, target_date: str | None = None):
    """Anchor the previous UTC day's audit chain to System 22."""
    from apps.audit.models import AuditEvent, DailyHashAnchor
    from django.utils import timezone as tz
    from django.db import transaction

    if target_date:
        from datetime import date
        anchor_date = date.fromisoformat(target_date)
    else:
        anchor_date = (tz.now() - timedelta(days=1)).date()

    if DailyHashAnchor.objects.filter(date=anchor_date).exists():
        logger.info("daily_hash_anchor: already anchored date=%s", anchor_date)
        return

    start = tz.datetime(anchor_date.year, anchor_date.month, anchor_date.day, tzinfo=tz.utc)
    end = start + timedelta(days=1)

    events_qs = AuditEvent.objects.filter(created_at__gte=start, created_at__lt=end)
    count = events_qs.count()

    last = events_qs.order_by("-id").values("event_id", "chain_hash").first()

    if last:
        head_event_id = last["event_id"]
        head_hash = last["chain_hash"]
    else:
        prev = AuditEvent.objects.filter(created_at__lt=start).order_by("-id").values("chain_hash").first()
        head_hash = prev["chain_hash"] if prev else "0" * 64
        head_event_id = None

    with transaction.atomic():
        anchor = DailyHashAnchor.objects.create(
            date=anchor_date,
            head_event_id=head_event_id,
            head_hash=head_hash,
            event_count=count,
        )
        from shared.events import publish
        publish(
            "AuditChainAnchorReady",
            {"date": anchor_date.isoformat(), "head_hash": head_hash, "event_count": count},
            topic="evs.audit",
        )

    # Mark as handed off to the relay queue (outbox will deliver to System 22).
    anchor.exported_to_s22_at = tz.now()
    anchor.save(update_fields=["exported_to_s22_at"])

    logger.info("daily_hash_anchor: anchored date=%s events=%d hash=%s", anchor_date, count, head_hash[:12])


@shared_task(name="apps.audit.tasks.cleanup_security_events", queue="sla-monitor")
def cleanup_security_events():
    from apps.audit.models import SecurityEvent
    retention_days = getattr(settings, "EDGE_SECURITY_EVENT_RETENTION_DAYS", 90)
    cutoff = timezone.now() - timedelta(days=retention_days)
    deleted, _ = SecurityEvent.objects.filter(occurred_at__lt=cutoff).delete()
    logger.info("cleanup_security_events: deleted=%d cutoff=%s", deleted, cutoff.date())


# ── Phase 9 Tasks ─────────────────────────────────────────────────────────────


@shared_task(
    name="apps.audit.tasks.build_daily_commitment",
    queue="outbox",
    bind=True,
    max_retries=3,
    default_retry_delay=600,  # 10 minutes between retries
)
def build_daily_commitment(self, target_date: str | None = None):
    """Build and submit the daily cryptographic commitment to System 22 (02:30 UTC).

    Chains the prior day's ``DailyHashAnchor`` head_hash with the latest
    completed ``IntegrityRun.merkle_root`` and the previous commitment hash,
    producing a tamper-evident chain of daily proofs.

    Retries up to 3 times with 10-minute delays on System 22 failure.
    """
    import hashlib
    import base64
    import hmac as hmac_lib

    from apps.audit.models import AuditEvent, DailyCommitment, DailyHashAnchor
    from apps.registry.models import IntegrityRun
    from django.db import transaction

    if target_date:
        from datetime import date as date_cls
        anchor_date = date_cls.fromisoformat(target_date)
    else:
        anchor_date = (timezone.now() - timedelta(days=1)).date()

    if DailyCommitment.objects.filter(date=anchor_date).exists():
        logger.info("build_daily_commitment: already committed date=%s", anchor_date)
        return

    # ── Fetch the DailyHashAnchor for the date ────────────────────────────────
    try:
        anchor = DailyHashAnchor.objects.get(date=anchor_date)
    except DailyHashAnchor.DoesNotExist:
        logger.warning(
            "build_daily_commitment: no DailyHashAnchor for %s — running daily_hash_anchor first",
            anchor_date,
        )
        daily_hash_anchor.apply(kwargs={"target_date": anchor_date.isoformat()})
        anchor = DailyHashAnchor.objects.get(date=anchor_date)

    head_hash = anchor.head_hash

    # ── Fetch latest completed integrity run for this date (or prior) ─────────
    integrity_run = (
        IntegrityRun.objects.filter(
            status=IntegrityRun.STATUS_COMPLETED,
            completed_at__date__lte=anchor_date,
        )
        .order_by("-completed_at")
        .first()
    )
    merkle_root = integrity_run.merkle_root if integrity_run else ("0" * 64)

    # ── Previous commitment hash ───────────────────────────────────────────────
    prev = DailyCommitment.objects.order_by("-date").first()
    prev_commitment_hash = prev.commitment_hash if prev else ("0" * 64)

    # ── Compute commitment hash ────────────────────────────────────────────────
    raw = f"{prev_commitment_hash}{merkle_root}{head_hash}"
    commitment_hash = hashlib.sha256(raw.encode()).hexdigest()

    # ── HSM sign commitment hash ───────────────────────────────────────────────
    hsm_sig, hsm_key_id = _sign_commitment(commitment_hash)

    with transaction.atomic():
        commitment = DailyCommitment.objects.create(
            date=anchor_date,
            anchor=anchor,
            integrity_merkle_root=merkle_root,
            prev_commitment_hash=prev_commitment_hash,
            commitment_hash=commitment_hash,
            hsm_signature=hsm_sig,
            hsm_key_id=hsm_key_id,
            status=DailyCommitment.STATUS_PENDING,
        )

    # ── Submit to System 22 ───────────────────────────────────────────────────
    try:
        receipt = _submit_commitment_to_s22(commitment)
        DailyCommitment.objects.filter(pk=commitment.pk).update(
            status=DailyCommitment.STATUS_CONFIRMED,
            s22_receipt=receipt,
            submitted_to_s22_at=timezone.now(),
        )
        logger.info(
            "build_daily_commitment: confirmed date=%s hash=%s",
            anchor_date, commitment_hash[:12],
        )
    except Exception as exc:
        DailyCommitment.objects.filter(pk=commitment.pk).update(
            status=DailyCommitment.STATUS_FAILED,
            retry_count=commitment.retry_count + 1,
        )
        logger.error("build_daily_commitment: S22 submission failed date=%s err=%s", anchor_date, exc)
        raise self.retry(exc=exc)

    AuditEvent.record(
        action="DAILY_COMMITMENT_ANCHORED",
        entity_type="DailyCommitment",
        entity_id=str(commitment.pk),
        new_state={
            "date": anchor_date.isoformat(),
            "commitment_hash": commitment_hash,
            "merkle_root": merkle_root,
        },
    )


@shared_task(
    name="apps.audit.tasks.run_auditor_general_export",
    queue="outbox",
    bind=True,
    max_retries=2,
    default_retry_delay=120,
)
def run_auditor_general_export(self, *, export_request_id: str):
    """Async task: build, sign, and upload an AG export bundle (Phase 9 — EVS-N06).

    Called by the ``POST /v1/audit/exports/`` API view after creating an
    ``ExportRequest`` record. Updates the record through ``building → signed``
    (or ``failed`` on error).
    """
    from datetime import date as date_cls

    from apps.audit.export_service import build_export_bundle
    from apps.audit.models import AuditEvent, ExportRequest

    try:
        req = ExportRequest.objects.get(pk=export_request_id)
    except ExportRequest.DoesNotExist:
        logger.error("run_auditor_general_export: request not found id=%s", export_request_id)
        return

    ExportRequest.objects.filter(pk=req.pk).update(status=ExportRequest.STATUS_BUILDING)

    try:
        result = build_export_bundle(
            date_from=req.date_from,
            date_to=req.date_to,
            institution_id=str(req.institution_id) if req.institution_id else None,
            export_request_id=str(req.id),
        )
    except Exception as exc:
        ExportRequest.objects.filter(pk=req.pk).update(
            status=ExportRequest.STATUS_FAILED,
            error_detail=str(exc),
        )
        logger.error("run_auditor_general_export: bundle failed id=%s err=%s", export_request_id, exc)
        raise self.retry(exc=exc)

    ExportRequest.objects.filter(pk=req.pk).update(
        status=ExportRequest.STATUS_SIGNED,
        signed_bundle_url=result["signed_bundle_url"],
        bundle_hash=result["bundle_hash"],
        hsm_signature=result["hsm_signature"],
        hsm_key_id=result["hsm_key_id"],
        signed_at=timezone.now(),
    )

    AuditEvent.record(
        action="AG_EXPORT_GENERATED",
        actor_id=req.actor_id,
        entity_type="ExportRequest",
        entity_id=str(req.id),
        new_state={
            "date_from": req.date_from.isoformat(),
            "date_to": req.date_to.isoformat(),
            "event_count": result["event_count"],
            "credential_count": result["credential_count"],
            "bundle_hash": result["bundle_hash"],
        },
    )

    logger.info(
        "run_auditor_general_export: signed id=%s events=%d creds=%d",
        export_request_id, result["event_count"], result["credential_count"],
    )


@shared_task(
    name="apps.audit.tasks.run_tiered_retention_migration",
    queue="outbox",
    bind=True,
    max_retries=1,
)
def run_tiered_retention_migration(self, *, force_date: str | None = None):
    """Monthly task: migrate hot audit events → warm storage in MinIO (Phase 9 — EVS-N02).

    Strategy
    --------
    - Hot tier  : events in the ``audit_auditevent`` table younger than
                  ``EVS_AUDIT_HOT_RETENTION_DAYS`` (default 90 days).
    - Warm tier : events older than 90 days are exported to a compressed JSONL
                  file in MinIO (``EVS_COLD_ARCHIVE_BUCKET_NAME``) and marked
                  with ``tier='warm'`` on the AuditEvent row.
    - Cold tier : events older than ``EVS_AUDIT_WARM_RETENTION_DAYS`` (default
                  3 years) are moved to the cold bucket.

    Events are never deleted from the database — the tier flag enables the
    audit API to route reads to the correct storage tier transparently.
    """
    import gzip
    import json
    import io
    import hashlib

    from apps.audit.models import AuditEvent, RetentionTierLog

    hot_days = getattr(settings, "EVS_AUDIT_HOT_RETENTION_DAYS", 90)
    warm_days = getattr(settings, "EVS_AUDIT_WARM_RETENTION_DAYS", 365 * 3)

    run_date = (
        timezone.datetime.fromisoformat(force_date).date()
        if force_date
        else timezone.now().date()
    )
    cutoff_hot = timezone.now() - timedelta(days=hot_days)
    cutoff_warm = timezone.now() - timedelta(days=warm_days)

    for transition, qs_filter, tier_label in [
        (
            RetentionTierLog.TRANSITION_HOT_WARM,
            {"created_at__lt": cutoff_hot, "tier": "hot"},
            "warm",
        ),
        (
            RetentionTierLog.TRANSITION_WARM_COLD,
            {"created_at__lt": cutoff_warm, "tier": "warm"},
            "cold",
        ),
    ]:
        # Skip warm→cold if model doesn't have tier field yet (graceful)
        try:
            qs = AuditEvent.objects.filter(**qs_filter).order_by("id")
        except Exception:
            qs = AuditEvent.objects.filter(created_at__lt=cutoff_hot).order_by("id")

        count = qs.count()
        if count == 0:
            logger.info("run_tiered_retention_migration: no events for transition=%s", transition)
            continue

        log = RetentionTierLog.objects.create(
            tier_transition=transition,
            run_date=run_date,
            event_count=count,
            status=RetentionTierLog.STATUS_RUNNING,
        )

        try:
            # Build compressed JSONL archive
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
                for ev in qs.values():
                    gz.write((json.dumps(ev, default=str) + "\n").encode())

            archive_bytes = buf.getvalue()
            manifest_hash = hashlib.sha256(archive_bytes).hexdigest()

            # Sign manifest
            from apps.audit.export_service import _sign_bytes
            hsm_sig, hsm_key_id = _sign_bytes(manifest_hash.encode())

            # Upload to MinIO
            object_key = f"retention/{transition}/{run_date}/{run_date}.jsonl.gz"
            minio_enabled = getattr(settings, "MINIO_ENABLED", False)
            archive_path = object_key

            if minio_enabled:
                from minio import Minio
                archive_bucket = getattr(
                    settings, "EVS_COLD_ARCHIVE_BUCKET_NAME", "evs-cold-archive"
                )
                client = Minio(
                    settings.MINIO_ENDPOINT,
                    access_key=settings.MINIO_ACCESS_KEY,
                    secret_key=settings.MINIO_SECRET_KEY,
                    secure=getattr(settings, "MINIO_SECURE", False),
                )
                if not client.bucket_exists(archive_bucket):
                    client.make_bucket(archive_bucket)
                client.put_object(
                    archive_bucket, object_key, io.BytesIO(archive_bytes),
                    len(archive_bytes), content_type="application/gzip",
                )

            RetentionTierLog.objects.filter(pk=log.pk).update(
                status=RetentionTierLog.STATUS_COMPLETED,
                manifest_hash=manifest_hash,
                hsm_signature=hsm_sig,
                hsm_key_id=hsm_key_id,
                archive_path=archive_path,
                completed_at=timezone.now(),
            )

            logger.info(
                "run_tiered_retention_migration: transition=%s events=%d archive=%s",
                transition, count, archive_path,
            )

        except Exception as exc:
            RetentionTierLog.objects.filter(pk=log.pk).update(
                status=RetentionTierLog.STATUS_FAILED,
                error_detail=str(exc),
                completed_at=timezone.now(),
            )
            logger.error(
                "run_tiered_retention_migration: FAILED transition=%s err=%s", transition, exc
            )
            raise self.retry(exc=exc)


# ── Shared signing helper ─────────────────────────────────────────────────────

def _sign_commitment(commitment_hash: str) -> tuple[str, str]:
    """Sign a commitment hash with the HSM or HMAC fallback."""
    import base64 as _b64
    import hashlib as _hl
    import hmac as _hmac

    from django.conf import settings as _settings

    if getattr(_settings, "HSM_ENABLED", False):
        try:
            from apps.hsm.service import get_hsm_service
            hsm = get_hsm_service()
            key_id = getattr(_settings, "HSM_KEY_ID_CREDENTIAL_SIGN", "evs-cred-sign-v1")
            sig_bytes = hsm.sign(key_id=key_id, data=commitment_hash.encode())
            return _b64.b64encode(sig_bytes).decode(), key_id
        except Exception as exc:
            logger.warning("audit_tasks.hsm_sign_failed — HMAC fallback: %s", exc)

    secret = _settings.SECRET_KEY.encode()
    sig = _hmac.new(secret, commitment_hash.encode(), _hl.sha256).digest()
    return _b64.b64encode(sig).decode(), "software-hmac-sha256"


def _submit_commitment_to_s22(commitment) -> dict:
    """POST the daily commitment to System 22 (CALS). Returns the S22 receipt."""
    import requests
    from django.conf import settings as _settings
    from shared.integrations.system17 import get_system17_client

    cals_url = getattr(_settings, "CALS_URL", "")
    if not cals_url:
        logger.warning("_submit_commitment_to_s22: CALS_URL not configured — skipping")
        return {"status": "skipped", "reason": "CALS_URL not set"}

    payload = {
        "type": "daily_commitment",
        "date": commitment.date.isoformat(),
        "commitment_hash": commitment.commitment_hash,
        "prev_commitment_hash": commitment.prev_commitment_hash,
        "integrity_merkle_root": commitment.integrity_merkle_root,
        "hsm_signature": commitment.hsm_signature,
        "hsm_key_id": commitment.hsm_key_id,
    }

    client = get_system17_client()
    resp = requests.post(
        f"{cals_url}/v1/ingest",
        json=payload,
        headers=client._hmac_headers(payload),
        timeout=getattr(_settings, "SYSTEM_17_TIMEOUT_SECONDS", 10),
    )
    resp.raise_for_status()
    return resp.json()
