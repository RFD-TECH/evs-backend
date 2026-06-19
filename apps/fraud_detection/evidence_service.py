"""Evidence package assembly for fraud flags (EVS-F05-06)."""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from django.utils import timezone

from .models import FlagAction, FraudFlag

logger = logging.getLogger(__name__)

IMMUTABLE_FIELDS = frozenset([
    "full_name", "date_of_birth", "institution_code", "graduate_index_number",
    "award_date", "degree_classification", "programme_code", "waec_index",
])


def assemble_evidence(flag: FraudFlag, actor_id=None) -> dict:
    """Build the complete evidence package for a flag.

    The package is deterministic — same flag state produces the same output.
    Returns a dict that can be JSON-serialised and stored / transmitted.
    """
    from apps.registry.models import Credential

    credentials = list(
        Credential.objects.filter(pk__in=flag.credential_ids)
        .only("id", "credential_ref", "institution_id", "candidate_id",
              "payload", "status", "sha256_hash", "created_at")
    )

    records = [_credential_snapshot(c) for c in credentials]
    field_diff = _diff_records(records)
    timeline = _build_timeline(flag)

    package = {
        "flag_id": str(flag.id),
        "flag_type": flag.flag_type,
        "severity": flag.severity,
        "status": flag.status,
        "created_at": flag.created_at.isoformat(),
        "assembled_at": timezone.now().isoformat(),
        "credential_records": records,
        "field_diff": field_diff,
        "detection_evidence": flag.evidence_payload,
        "fuzzy_similarity_score": flag.fuzzy_similarity_score,
        "timeline": timeline,
        "rule_id": str(flag.rule_id) if flag.rule_id else None,
        "run_id": str(flag.run_id) if flag.run_id else None,
    }

    package["package_sha256"] = _hash_package(package)

    # Update the flag record with the computed hash and log a view action
    if actor_id:
        FlagAction.objects.create(
            flag=flag,
            actor_user_id=actor_id,
            action=FlagAction.ACTION_VIEWED,
            payload={"package_sha256": package["package_sha256"]},
        )

    return package


def _credential_snapshot(credential) -> dict:
    """Safe, auditable snapshot of a credential for the evidence bundle."""
    payload = credential.payload or {}
    return {
        "id": str(credential.id),
        "credential_ref": credential.credential_ref,
        "institution_id": str(credential.institution_id) if credential.institution_id else None,
        "candidate_id": str(credential.candidate_id) if credential.candidate_id else None,
        "sha256_hash": credential.sha256_hash,
        "status": credential.status,
        "created_at": credential.created_at.isoformat() if credential.created_at else None,
        "payload_fields": {k: payload.get(k) for k in IMMUTABLE_FIELDS if k in payload},
    }


def _diff_records(records: list[dict]) -> dict:
    """Return only the fields that differ across the set of credential records."""
    if len(records) < 2:
        return {}

    all_payload_keys: set[str] = set()
    for r in records:
        all_payload_keys.update(r.get("payload_fields", {}).keys())

    diff: dict[str, list[Any]] = {}
    for key in sorted(all_payload_keys):
        values = [r.get("payload_fields", {}).get(key) for r in records]
        if len({str(v) for v in values}) > 1:
            diff[key] = values
    return diff


def _build_timeline(flag: FraudFlag) -> list[dict]:
    """Ordered list of all FlagActions for the flag (audit trail view)."""
    actions = flag.actions.order_by("occurred_at").values(
        "id", "action", "actor_user_id", "occurred_at", "payload", "audit_chain_ref"
    )
    return [
        {
            "id": str(a["id"]),
            "action": a["action"],
            "actor_user_id": str(a["actor_user_id"]) if a["actor_user_id"] else None,
            "occurred_at": a["occurred_at"].isoformat(),
            "payload": a["payload"],
            "audit_chain_ref": a["audit_chain_ref"],
        }
        for a in actions
    ]


def _hash_package(package: dict) -> str:
    """Deterministic SHA-256 of the evidence package (excludes the hash itself)."""
    body = {k: v for k, v in package.items() if k != "package_sha256"}
    serialised = json.dumps(body, sort_keys=True, default=str)
    return hashlib.sha256(serialised.encode()).hexdigest()


def add_addendum(
    *,
    flag: FraudFlag,
    actor_id,
    note: str,
    additional_evidence: dict | None = None,
) -> FlagAction:
    """Attach an addendum to an already-resolved or open flag."""
    if not note.strip():
        raise ValueError("Addendum note must not be empty.")

    current_evidence = flag.evidence_payload or {}
    addenda = current_evidence.get("addenda", [])
    addenda.append({
        "actor_id": str(actor_id),
        "note": note,
        "added_at": timezone.now().isoformat(),
        "additional_evidence": additional_evidence or {},
    })
    current_evidence["addenda"] = addenda
    flag.evidence_payload = current_evidence
    flag.save(update_fields=["evidence_payload", "updated_at"])

    action = FlagAction.objects.create(
        flag=flag,
        actor_user_id=actor_id,
        action=FlagAction.ACTION_ADDENDUM,
        payload={"note": note, "additional_evidence_keys": list((additional_evidence or {}).keys())},
    )
    return action
