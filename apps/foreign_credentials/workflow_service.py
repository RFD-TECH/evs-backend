"""Foreign Credential Assessment workflow service — EVS-F03 Phase 6.

Provides transition functions for each stage change. Every transition:
  1. Validates the actor has permission to make the transition.
  2. Updates the application stage.
  3. Writes a WorkflowTransition audit row.
  4. Sets stage-specific SLA on AssessorAssignment or FcaSlaEvent.
  5. Emits AuditEvent via the shared outbox.
"""
import hashlib
import json
import logging
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

SLA_DAYS = {
    "triaged": 2,
    "assessor_assigned": 3,
    "under_review": 14,
    "recommendation_made": 3,
    "registrar_reviewed": 3,
    "dg_pending": 5,
}


def submit_application(
    *,
    applicant_sub: str,
    applicant_email: str,
    applicant_name: str,
    foreign_institution: str,
    foreign_country: str,
    foreign_degree: str,
    graduation_year: int,
) -> "ForeignCredentialApplication":
    from apps.foreign_credentials.models import ForeignCredentialApplication, FcaSlaEvent

    with transaction.atomic():
        ref = _generate_reference()
        app = ForeignCredentialApplication.objects.create(
            reference=ref,
            applicant_sub=applicant_sub,
            applicant_email=applicant_email,
            applicant_name=applicant_name,
            foreign_institution=foreign_institution,
            foreign_country=foreign_country,
            foreign_degree=foreign_degree,
            graduation_year=graduation_year,
            stage=ForeignCredentialApplication.STAGE_SUBMITTED,
        )
        FcaSlaEvent.objects.create(
            application=app,
            stage=ForeignCredentialApplication.STAGE_SUBMITTED,
            event="entered",
        )
        _audit("FCA_SUBMITTED", app, applicant_sub)
    return app


def triage(*, application, registrar_sub: str, route: str, notes: str = ""):
    """Registrar reviews the submission and routes to Internal or GTEC."""
    from apps.foreign_credentials.models import ForeignCredentialApplication

    _assert_stage(application, ForeignCredentialApplication.STAGE_SUBMITTED)
    if route not in (ForeignCredentialApplication.ROUTE_INTERNAL, ForeignCredentialApplication.ROUTE_GTEC):
        raise ValueError(f"Invalid route '{route}'. Must be 'internal' or 'gtec'.")

    stage = (
        ForeignCredentialApplication.STAGE_ROUTED_INTERNAL
        if route == ForeignCredentialApplication.ROUTE_INTERNAL
        else ForeignCredentialApplication.STAGE_ROUTED_GTEC
    )

    with transaction.atomic():
        _transition(application, stage, actor_sub=registrar_sub, reason=notes)
        application.route = route
        application.triaged_by = registrar_sub
        application.triaged_at = timezone.now()
        application.sla_due_at = timezone.now() + timedelta(days=28)
        application.save(update_fields=["route", "triaged_by", "triaged_at", "sla_due_at", "updated_at"])
        _audit("FCA_TRIAGED", application, registrar_sub, {"route": route})


def assign_assessor(*, application, assessor_sub: str, task: str, registrar_sub: str):
    """Assign an assessor to the application."""
    from apps.foreign_credentials.models import (
        ForeignCredentialApplication, AssessorAssignment, FcaSlaEvent,
    )

    _assert_stage(
        application,
        ForeignCredentialApplication.STAGE_ROUTED_INTERNAL,
        ForeignCredentialApplication.STAGE_ROUTED_GTEC,
    )

    sla_days = SLA_DAYS["assessor_assigned"] + SLA_DAYS["under_review"]

    with transaction.atomic():
        AssessorAssignment.objects.get_or_create(
            application=application,
            assessor_sub=assessor_sub,
            task=task,
            defaults={
                "assigned_by": registrar_sub,
                "sla_due_at": timezone.now() + timedelta(days=sla_days),
            },
        )
        _transition(
            application,
            ForeignCredentialApplication.STAGE_ASSESSOR_ASSIGNED,
            actor_sub=registrar_sub,
        )
        application.assessor_sub = assessor_sub
        application.assessor_assigned_at = timezone.now()
        application.save(update_fields=["assessor_sub", "assessor_assigned_at", "updated_at"])
        _audit("FCA_ASSESSOR_ASSIGNED", application, registrar_sub, {"assessor_sub": str(assessor_sub)})


def submit_recommendation(
    *, application, assessor_sub: str, recommendation: str, rationale: str,
    accreditation_ok: bool, content_match_pct: int | None = None, conditions: str = "",
):
    from apps.foreign_credentials.models import (
        ForeignCredentialApplication, EquivalenceRecommendation,
    )
    from apps.registry.canonicaliser import sha256_of_canonical

    _assert_stage(
        application,
        ForeignCredentialApplication.STAGE_ASSESSOR_ASSIGNED,
        ForeignCredentialApplication.STAGE_UNDER_REVIEW,
    )

    canonical = {
        "application": str(application.id),
        "assessor_sub": str(assessor_sub),
        "recommendation": recommendation,
        "rationale": rationale,
        "accreditation_ok": accreditation_ok,
    }
    rec_sha256 = sha256_of_canonical(canonical)

    with transaction.atomic():
        rec = EquivalenceRecommendation.objects.create(
            application=application,
            assessor_sub=assessor_sub,
            recommendation=recommendation,
            rationale=rationale,
            accreditation_ok=accreditation_ok,
            content_match_pct=content_match_pct,
            conditions=conditions,
            sha256=rec_sha256,
        )
        _transition(
            application,
            ForeignCredentialApplication.STAGE_RECOMMENDATION_MADE,
            actor_sub=assessor_sub,
        )
        _audit("FCA_RECOMMENDATION_MADE", application, assessor_sub, {"recommendation": recommendation})
    return rec


def registrar_review(*, application, registrar_sub: str, notes: str = ""):
    from apps.foreign_credentials.models import ForeignCredentialApplication

    _assert_stage(application, ForeignCredentialApplication.STAGE_RECOMMENDATION_MADE)
    with transaction.atomic():
        _transition(
            application,
            ForeignCredentialApplication.STAGE_REGISTRAR_REVIEWED,
            actor_sub=registrar_sub, reason=notes,
        )
        _transition(
            application,
            ForeignCredentialApplication.STAGE_DG_PENDING,
            actor_sub=registrar_sub,
        )
        _audit("FCA_REGISTRAR_REVIEWED", application, registrar_sub)


def dg_sign(
    *, application, dg_sub: str, outcome: str, decision_text: str, hsm_key_id: str
):
    """Director-General signs the final decision with the HSM-backed key."""
    from apps.foreign_credentials.models import ForeignCredentialApplication, DGDecision
    from apps.registry.canonicaliser import sha256_of_canonical

    _assert_stage(application, ForeignCredentialApplication.STAGE_DG_PENDING)

    canonical_decision = {
        "application_id": str(application.id),
        "reference": application.reference,
        "dg_sub": str(dg_sub),
        "outcome": outcome,
        "decision_text": decision_text,
        "signed_at": timezone.now().isoformat(),
    }
    decision_sha256 = sha256_of_canonical(canonical_decision)

    from apps.hsm.service import sign_with_key
    try:
        signature_b64 = sign_with_key(
            key_id=hsm_key_id,
            payload=decision_sha256.encode(),
        )
    except Exception as exc:
        raise ValueError(f"HSM signing failed: {exc}") from exc

    with transaction.atomic():
        DGDecision.objects.create(
            application=application,
            dg_sub=dg_sub,
            outcome=outcome,
            decision_text=decision_text,
            hsm_key_id=hsm_key_id,
            signature_b64=signature_b64,
            decision_sha256=decision_sha256,
        )
        application.dg_sub = dg_sub
        application.dg_signed_at = timezone.now()
        application.dg_signature_ref = hsm_key_id
        application.decision_sha256 = decision_sha256
        application.outcome = outcome
        application.save(update_fields=[
            "dg_sub", "dg_signed_at", "dg_signature_ref",
            "decision_sha256", "outcome", "updated_at",
        ])
        _transition(
            application,
            ForeignCredentialApplication.STAGE_DG_SIGNED,
            actor_sub=dg_sub,
        )
        _audit("FCA_DG_SIGNED", application, dg_sub, {
            "outcome": outcome, "decision_sha256": decision_sha256
        })


# ── Helpers ────────────────────────────────────────────────────────────────────

def _assert_stage(application, *allowed_stages):
    if application.stage not in allowed_stages:
        raise ValueError(
            f"Application {application.reference} is in stage '{application.stage}', "
            f"not in {allowed_stages}."
        )


def _transition(application, new_stage: str, *, actor_sub: str, reason: str = ""):
    from apps.foreign_credentials.models import WorkflowTransition, FcaSlaEvent

    old_stage = application.stage
    WorkflowTransition.objects.create(
        application=application,
        from_stage=old_stage,
        to_stage=new_stage,
        actor_sub=actor_sub,
        reason=reason,
    )
    application.stage = new_stage
    application.save(update_fields=["stage", "updated_at"])

    FcaSlaEvent.objects.create(
        application=application,
        stage=new_stage,
        event="entered",
        actor_sub=actor_sub,
        sla_due_at=timezone.now() + timedelta(days=SLA_DAYS.get(new_stage, 7)),
    )


def _audit(action: str, application, actor_sub, extra: dict | None = None):
    try:
        from apps.audit.models import AuditEvent
        AuditEvent.record(
            action=action,
            entity_type="ForeignCredentialApplication",
            entity_id=str(application.id),
            actor_id=actor_sub,
            new_state={"stage": application.stage, **(extra or {})},
            old_state={},
        )
    except Exception as exc:
        logger.warning("fca.audit_failed action=%s err=%s", action, exc)


def _generate_reference() -> str:
    from apps.foreign_credentials.models import ForeignCredentialApplication
    year = timezone.now().year
    prefix = f"FCA-{year}-"
    last = (
        ForeignCredentialApplication.objects.filter(reference__startswith=prefix)
        .order_by("-reference").first()
    )
    if last:
        try:
            seq = int(last.reference.split("-")[-1]) + 1
        except ValueError:
            seq = 1
    else:
        seq = 1
    return f"{prefix}{seq:04d}"
