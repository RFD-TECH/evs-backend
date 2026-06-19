"""Legacy credential ingest service (EVS-F09-02).

Transforms raw legacy records into Credential objects that are:
- Identical to contemporary awards in verification path
- Marked legacy=True with the source wave_id
- Assigned the same UUID, SHA-256, and QR as would be generated today
- Stored with CredentialVersion v1 as the original snapshot
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid as _uuid
from typing import Any

from django.db import transaction
from django.utils import timezone

from apps.registry.models import Credential
from .models import CredentialVersion, LegacyBatch, LegacyConfirmation, MigrationWave

logger = logging.getLogger(__name__)

REQUIRED_FIELDS = {
    "full_name", "date_of_birth", "institution_code",
    "graduate_index_number", "award_date", "degree_classification",
}


# ── Affidavit enforcement ─────────────────────────────────────────────────────

def assert_affidavit_verified(batch: LegacyBatch) -> None:
    """Raise if the batch's affidavit has not been verified by a Registrar."""
    if not batch.affidavit_verified:
        raise ValueError(
            f"Batch {batch.batch_ref} may not proceed: "
            "affidavit must be verified by a Registrar first (EVS-F09-02)."
        )


# ── Ingest orchestrator ───────────────────────────────────────────────────────

def ingest_batch(
    *,
    wave: MigrationWave,
    records: list[dict[str, Any]],
    uploaded_by,
    file_name: str,
    file_sha256: str,
    affidavit_ref: str,
) -> LegacyBatch:
    """Create a LegacyBatch and ingest all records. Returns the batch.

    Records that fail validation are recorded in batch.error_summary but do
    not abort the rest of the batch (partial success is allowed).
    """
    if wave.status not in (MigrationWave.STATUS_ACTIVE,):
        raise ValueError(
            f"Wave '{wave.name}' is not in Active state (current: {wave.status}). "
            "Only Active waves accept batch uploads."
        )

    batch_ref = _generate_batch_ref(wave)
    batch = LegacyBatch.objects.create(
        wave=wave,
        batch_ref=batch_ref,
        uploaded_by=uploaded_by,
        file_name=file_name,
        file_sha256=file_sha256,
        record_count=len(records),
        affidavit_ref=affidavit_ref,
        status=LegacyBatch.STATUS_PROCESSING,
    )

    ingested = 0
    errors: dict[int, str] = {}

    for idx, raw in enumerate(records):
        try:
            _ingest_record(raw, batch=batch, wave=wave)
            ingested += 1
        except Exception as exc:
            logger.warning("Batch %s record %d ingest error: %s", batch_ref, idx, exc)
            errors[idx] = str(exc)

    batch.ingested_count = ingested
    batch.error_summary = {"errors": errors, "error_count": len(errors)}
    batch.status = (
        LegacyBatch.STATUS_AWAITING_CONFIRMATION
        if ingested > 0
        else LegacyBatch.STATUS_REJECTED
    )
    batch.save()

    logger.info(
        "Batch %s: %d/%d ingested, %d errors", batch_ref, ingested, len(records), len(errors)
    )
    return batch


def _ingest_record(raw: dict, *, batch: LegacyBatch, wave: MigrationWave) -> Credential:
    """Validate, normalise, and persist a single legacy record."""
    _validate_record(raw)

    payload = _normalise_payload(raw)
    cred_id = _uuid.uuid4()
    sha256 = _compute_sha256(cred_id, payload)
    qr_payload = _build_qr_payload(cred_id, payload)

    with transaction.atomic():
        cred = Credential.objects.create(
            id=cred_id,
            credential_ref=_build_credential_ref(payload),
            institution_id=_resolve_institution_id(payload),
            candidate_id=None,
            payload=payload,
            sha256_hash=sha256,
            qr_payload=qr_payload,
            status=Credential.STATUS_ACTIVE,
            batch_id=batch.id,
            legacy=True,
            wave_id=wave.id,
        )
        CredentialVersion.objects.create(
            credential_id=cred.id,
            version=1,
            payload_snapshot=payload,
            sha256_at_version=sha256,
            change_reason="Legacy ingest — original record",
        )
    return cred


def _validate_record(raw: dict) -> None:
    missing = REQUIRED_FIELDS - set(raw.keys())
    if missing:
        raise ValueError(f"Missing required fields: {sorted(missing)}")
    if not str(raw.get("full_name", "")).strip():
        raise ValueError("full_name must not be blank.")
    if not str(raw.get("graduate_index_number", "")).strip():
        raise ValueError("graduate_index_number must not be blank.")


def _normalise_payload(raw: dict) -> dict:
    return {
        "full_name": str(raw["full_name"]).strip(),
        "date_of_birth": str(raw.get("date_of_birth", "")).strip(),
        "institution_code": str(raw.get("institution_code", "")).strip().upper(),
        "graduate_index_number": str(raw["graduate_index_number"]).strip().upper(),
        "award_date": str(raw.get("award_date", "")).strip(),
        "degree_classification": str(raw.get("degree_classification", "")).strip(),
        "programme_code": str(raw.get("programme_code", "")).strip(),
        "waec_index": str(raw.get("waec_index", "")).strip(),
        **{k: v for k, v in raw.items()
           if k not in REQUIRED_FIELDS | {"programme_code", "waec_index"}},
    }


def _compute_sha256(cred_id, payload: dict) -> str:
    body = json.dumps({"id": str(cred_id), **payload}, sort_keys=True)
    return hashlib.sha256(body.encode()).hexdigest()


def _build_qr_payload(cred_id, payload: dict) -> str:
    return json.dumps({
        "id": str(cred_id),
        "ref": _build_credential_ref(payload),
        "institution_code": payload.get("institution_code"),
        "graduate_index_number": payload.get("graduate_index_number"),
    }, separators=(",", ":"))


def _build_credential_ref(payload: dict) -> str:
    inst = payload.get("institution_code", "UNK")
    idx = payload.get("graduate_index_number", "").replace("/", "-")
    return f"EVS-LGY-{inst}-{idx}"[:100]


def _resolve_institution_id(payload: dict):
    """Look up institution UUID by institution_code; returns None if not found."""
    code = payload.get("institution_code")
    if not code:
        return None
    try:
        from apps.institutions.models import Institution
        inst = Institution.objects.filter(code=code).values_list("id", flat=True).first()
        return inst
    except Exception:
        return None


def _generate_batch_ref(wave: MigrationWave) -> str:
    import random, string
    suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f"LB-{wave.name[:10].upper()}-{suffix}"


# ── Record correction ─────────────────────────────────────────────────────────

def correct_record(
    *,
    credential_id,
    patch: dict,
    changed_by,
    change_reason: str,
) -> Credential:
    """Apply a correction to a legacy credential, creating a new CredentialVersion."""
    cred = Credential.objects.get(pk=credential_id, legacy=True)

    old_payload = dict(cred.payload or {})
    new_payload = {**old_payload, **patch}

    last_version = (
        CredentialVersion.objects
        .filter(credential_id=credential_id)
        .order_by("-version")
        .values_list("version", flat=True)
        .first()
    ) or 0

    new_sha256 = _compute_sha256(cred.id, new_payload)

    with transaction.atomic():
        cred.payload = new_payload
        cred.sha256_hash = new_sha256
        cred.qr_payload = _build_qr_payload(cred.id, new_payload)
        cred.save()

        CredentialVersion.objects.create(
            credential_id=cred.id,
            version=last_version + 1,
            payload_snapshot=new_payload,
            sha256_at_version=new_sha256,
            changed_by=changed_by,
            change_reason=change_reason,
        )

    return cred
