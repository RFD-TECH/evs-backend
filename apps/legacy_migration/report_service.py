"""Pre-go-live dual-authority audit report service (EVS-F09-06)."""
from __future__ import annotations

import hashlib
import json
import logging

from django.db import transaction
from django.utils import timezone

from .models import LegacyBatch, LegacyConfirmation, MigrationAuditReport, MigrationWave

logger = logging.getLogger(__name__)


def generate_report(wave: MigrationWave, *, generated_by) -> MigrationAuditReport:
    """Generate (or regenerate) the draft audit report for a wave.

    Only allowed while wave is Active. Regenerating replaces the existing draft.
    """
    if wave.status not in (MigrationWave.STATUS_ACTIVE,):
        raise ValueError(
            f"Reports may only be generated for Active waves (current: {wave.status})."
        )

    payload = _build_report_payload(wave)

    existing = MigrationAuditReport.objects.filter(wave=wave).first()
    if existing and existing.status != MigrationAuditReport.STATUS_DRAFT:
        raise ValueError(
            "Report has already been signed. Create a new wave rather than regenerating."
        )

    with transaction.atomic():
        if existing:
            existing.report_payload = payload
            existing.generated_at = timezone.now()
            existing.generated_by = generated_by
            existing.save()
            report = existing
        else:
            report = MigrationAuditReport.objects.create(
                wave=wave,
                report_payload=payload,
                generated_by=generated_by,
            )

    return report


def sign_as_admin(report: MigrationAuditReport, *, signer_id) -> MigrationAuditReport:
    """First signature — Administrator leg of dual-control."""
    if report.status != MigrationAuditReport.STATUS_DRAFT:
        raise ValueError(f"Report is not in Draft state (current: {report.status}).")

    sig_hash = _compute_signature(report, signer_id, "admin")
    report.admin_signer_id = signer_id
    report.admin_signed_at = timezone.now()
    report.admin_signature_hash = sig_hash
    report.status = MigrationAuditReport.STATUS_ADMIN_SIGNED
    report.save()
    _audit(report, "MIGRATION_REPORT_ADMIN_SIGNED", signer_id)
    return report


def sign_as_registrar(report: MigrationAuditReport, *, signer_id) -> MigrationAuditReport:
    """Second signature — Registrar leg. Completes dual-control and anchors to System 22."""
    if report.status != MigrationAuditReport.STATUS_ADMIN_SIGNED:
        raise ValueError(
            f"Report must be Admin-Signed before Registrar can sign (current: {report.status})."
        )
    if str(signer_id) == str(report.admin_signer_id):
        raise ValueError("Registrar signer may not be the same person as the Admin signer.")

    sig_hash = _compute_signature(report, signer_id, "registrar")
    with transaction.atomic():
        report.registrar_signer_id = signer_id
        report.registrar_signed_at = timezone.now()
        report.registrar_signature_hash = sig_hash
        report.status = MigrationAuditReport.STATUS_FULLY_SIGNED
        report.save()

    chain_ref = _anchor_to_system22(report)
    if chain_ref:
        report.audit_chain_ref = chain_ref
        report.save(update_fields=["audit_chain_ref"])

    return report


def _build_report_payload(wave: MigrationWave) -> dict:
    batches = wave.batches.all()
    batch_data = list(batches.values("batch_ref", "status", "ingested_count",
                                     "confirmed_count", "rejected_count", "file_sha256"))

    total_ingested = sum(b["ingested_count"] for b in batch_data)
    total_confirmed = sum(b["confirmed_count"] for b in batch_data)
    total_rejected = sum(b["rejected_count"] for b in batch_data)
    unconfirmed_batches = [b["batch_ref"] for b in batch_data
                           if b["status"] != LegacyBatch.STATUS_CONFIRMED]

    # Parity check: do all legacy credentials have SHA-256 and QR?
    from apps.registry.models import Credential
    legacy_qs = Credential.objects.filter(wave_id=wave.id)
    total_legacy = legacy_qs.count()
    missing_hash = legacy_qs.filter(sha256_hash="").count()
    missing_qr = legacy_qs.filter(qr_payload="").count()

    # Anomaly summary from fraud flags touching these credentials
    from apps.fraud_detection.models import FraudFlag
    open_flags = FraudFlag.objects.filter(
        status__in=[FraudFlag.STATUS_NEW, FraudFlag.STATUS_UNDER_INVESTIGATION],
        credential_ids__overlap=[str(c) for c in legacy_qs.values_list("id", flat=True)[:1000]],
    ).count()

    return {
        "wave_id": str(wave.id),
        "wave_name": wave.name,
        "institution_id": str(wave.institution_id),
        "graduation_year_from": wave.graduation_year_from,
        "graduation_year_to": wave.graduation_year_to,
        "confirmation_deadline": wave.confirmation_deadline.isoformat(),
        "batch_count": batches.count(),
        "batches": batch_data,
        "unconfirmed_batches": unconfirmed_batches,
        "total_legacy_credentials": total_legacy,
        "total_ingested": total_ingested,
        "total_confirmed": total_confirmed,
        "total_rejected": total_rejected,
        "parity_check": {
            "missing_sha256": missing_hash,
            "missing_qr": missing_qr,
            "parity_ok": missing_hash == 0 and missing_qr == 0,
        },
        "open_fraud_flags": open_flags,
        "ready_for_go_live": (
            not unconfirmed_batches
            and missing_hash == 0
            and missing_qr == 0
            and open_flags == 0
        ),
    }


def _compute_signature(report: MigrationAuditReport, signer_id, role: str) -> str:
    body = json.dumps({
        "report_id": str(report.id),
        "wave_id": str(report.wave_id),
        "signer_id": str(signer_id),
        "role": role,
        "report_sha256": hashlib.sha256(
            json.dumps(report.report_payload, sort_keys=True).encode()
        ).hexdigest(),
        "signed_at": timezone.now().isoformat(),
    }, sort_keys=True)
    return hashlib.sha256(body.encode()).hexdigest()


def _anchor_to_system22(report: MigrationAuditReport) -> str | None:
    try:
        from apps.audit.models import AuditEvent
        event = AuditEvent.record(
            action="MIGRATION_REPORT_FULLY_SIGNED",
            entity_type="MigrationAuditReport",
            entity_id=str(report.id),
            actor_id=str(report.registrar_signer_id),
            new_state={
                "status": report.status,
                "admin_signer": str(report.admin_signer_id),
                "registrar_signer": str(report.registrar_signer_id),
                "wave_id": str(report.wave_id),
            },
            old_state={},
        )
        return str(event.id) if event else None
    except Exception as exc:
        logger.warning("Failed to anchor report %s to System 22: %s", report.id, exc)
        return None


def _audit(report: MigrationAuditReport, action: str, actor_id=None) -> None:
    try:
        from apps.audit.models import AuditEvent
        AuditEvent.record(
            action=action,
            entity_type="MigrationAuditReport",
            entity_id=str(report.id),
            actor_id=str(actor_id) if actor_id else None,
            new_state={"status": report.status},
            old_state={},
        )
    except Exception as exc:
        logger.warning("Failed to audit report %s: %s", report.id, exc)
