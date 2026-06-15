"""Registry business logic — batch ingest, credential registration, revocation."""
import csv
import hashlib
import io
import json
import logging
import uuid

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .canonicaliser import canonical_json, sha256_of_canonical
from .models import BatchIngest, Credential, CredentialSchemaVersion, RevocationRecord

logger = logging.getLogger(__name__)

_REQUIRED_FIELDS = ["credential_ref", "candidate_name", "programme", "graduation_year"]


def process_batch_ingest(batch: BatchIngest, file_bytes: bytes) -> None:
    """Parse file and register credentials. Partial success — valid rows committed."""
    batch.status = BatchIngest.STATUS_PROCESSING
    batch.save(update_fields=["status"])

    try:
        records = _parse_file(file_bytes, batch.file_format)
    except Exception as exc:
        batch.status = BatchIngest.STATUS_FAILED
        batch.row_errors = [{"error": f"File parse error: {exc}"}]
        batch.save(update_fields=["status", "row_errors"])
        return

    if len(records) > 10_000:
        batch.status = BatchIngest.STATUS_FAILED
        batch.row_errors = [{"error": f"Batch exceeds 10,000 record limit ({len(records)} rows)."}]
        batch.save(update_fields=["status", "row_errors"])
        return

    batch.total_records = len(records)
    success = 0
    failure = 0
    row_errors = []

    for row_num, record in enumerate(records, start=1):
        try:
            _register_one(record, batch)
            success += 1
        except Exception as exc:
            failure += 1
            row_errors.append({
                "row": row_num,
                "ref": record.get("credential_ref", ""),
                "error": str(exc),
            })

    batch.success_count = success
    batch.failure_count = failure
    batch.row_errors = row_errors
    batch.status = BatchIngest.STATUS_COMPLETED
    batch.completed_at = timezone.now()
    batch.save()

    _audit(
        action="BATCH_INGEST_COMPLETED",
        entity_type="BatchIngest",
        entity_id=str(batch.id),
        old_state={"status": "processing"},
        new_state={
            "status": "completed",
            "success": success,
            "failure": failure,
            "institution_id": str(batch.institution_id),
        },
    )


def revoke_credential(
    *,
    credential: Credential,
    actor_id: uuid.UUID,
    reason: str,
) -> RevocationRecord:
    """Revoke a credential and write an append-only RevocationRecord."""
    if credential.status == Credential.STATUS_REVOKED:
        raise ValueError("Credential is already revoked.")

    old_status = credential.status

    with transaction.atomic():
        credential.status = Credential.STATUS_REVOKED
        credential.revoked_at = timezone.now()
        credential.revoke_reason = reason
        credential.revoked_by = actor_id
        credential.save(update_fields=["status", "revoked_at", "revoke_reason", "revoked_by", "updated_at"])

        record = RevocationRecord.objects.create(
            credential=credential,
            revoked_by=actor_id,
            reason=reason,
        )

    _audit(
        action="CREDENTIAL_REVOKED",
        actor_id=actor_id,
        entity_type="Credential",
        entity_id=str(credential.id),
        old_state={"status": old_status},
        new_state={"status": "revoked", "reason": reason},
    )

    from shared.events import publish
    publish(
        "CredentialRevoked",
        {"credential_id": str(credential.id), "credential_ref": credential.credential_ref},
        topic="evs.registry",
    )

    return record


def quarantine_credential(*, credential: Credential, actor_id: uuid.UUID, reason: str) -> None:
    if credential.status == Credential.STATUS_REVOKED:
        raise ValueError("Cannot quarantine an already-revoked credential.")
    old_status = credential.status
    credential.status = Credential.STATUS_QUARANTINED
    credential.save(update_fields=["status", "updated_at"])
    _audit(
        action="CREDENTIAL_QUARANTINED",
        actor_id=actor_id,
        entity_type="Credential",
        entity_id=str(credential.id),
        old_state={"status": old_status},
        new_state={"status": "quarantined", "reason": reason},
    )


# ── Internal helpers ──────────────────────────────────────────────────────────

def _register_one(record: dict, batch: BatchIngest) -> Credential:
    """Validate, canonicalise, and store one credential record."""
    _validate_record(record, batch.schema_version)

    sha = sha256_of_canonical(record)
    if Credential.objects.filter(sha256_hash=sha).exists():
        raise ValueError(
            f"Duplicate credential — SHA-256 {sha[:12]}… already registered."
        )

    credential_id = uuid.uuid4()
    verify_base = getattr(settings, "EVS_VERIFY_BASE_URL", "https://evs.clet.gov.gh/verify")
    qr_url = f"{verify_base}/{credential_id}"

    cred = Credential.objects.create(
        id=credential_id,
        credential_ref=record["credential_ref"],
        schema_version=batch.schema_version,
        institution_id=batch.institution_id,
        graduation_cycle_id=batch.graduation_cycle_id,
        candidate_id=record.get("candidate_id"),
        payload=record,
        sha256_hash=sha,
        qr_url=qr_url,
        batch_id=batch.id,
        status=Credential.STATUS_ACTIVE,
    )

    from apps.registry.qr_tasks import sign_qr_jwt
    sign_qr_jwt.apply_async(kwargs={"credential_id": str(cred.id)}, queue="high-priority")

    _audit(
        action="CREDENTIAL_REGISTERED",
        entity_type="Credential",
        entity_id=str(cred.id),
        new_state={
            "credential_ref": cred.credential_ref,
            "sha256": sha,
            "batch_id": str(batch.id),
            "institution_id": str(batch.institution_id),
        },
    )

    return cred


def _validate_record(record: dict, schema_version: CredentialSchemaVersion) -> None:
    missing = [f for f in _REQUIRED_FIELDS if not record.get(f)]
    if missing:
        raise ValueError(f"Missing required fields: {', '.join(missing)}")

    if schema_version.required_fields:
        extra_missing = [f for f in schema_version.required_fields if not record.get(f)]
        if extra_missing:
            raise ValueError(f"Schema requires: {', '.join(extra_missing)}")


def _parse_file(file_bytes: bytes, file_format: str) -> list:
    if file_format == "json":
        data = json.loads(file_bytes)
        return data if isinstance(data, list) else [data]
    if file_format == "csv":
        reader = csv.DictReader(io.StringIO(file_bytes.decode("utf-8-sig")))
        return list(reader)
    raise ValueError(f"Unsupported file format: {file_format!r}")


def _audit(action: str, **kwargs):
    try:
        from apps.audit.models import AuditEvent
        AuditEvent.record(action=action, source_system="evs.registry", **kwargs)
    except Exception as exc:
        logger.warning("registry.audit_failed action=%s err=%s", action, exc)
