"""Fraud detection orchestrator — duplicate detection + rules evaluation (EVS-F05-01/02/03)."""
from __future__ import annotations

import logging
import re
import unicodedata
from collections import defaultdict
from datetime import datetime, timedelta, UTC

from django.db import transaction
from django.utils import timezone

from apps.registry.models import Credential
from .models import FlagAction, FraudFlag, RuleDefinition, RuleRun
from . import rules_engine as _engine

logger = logging.getLogger(__name__)

DEFAULT_FUZZY_THRESHOLD = 0.85
FUZZY_THRESHOLD_MIN = 0.5
FUZZY_THRESHOLD_MAX = 0.99


# ── Name normalisation ───────────────────────────────────────────────────────

def normalise_name(name: str) -> str:
    """Lowercase, NFC-normalise, strip diacritics, collapse whitespace."""
    if not name:
        return ""
    name = unicodedata.normalize("NFC", name.strip().lower())
    # NFD decomposition strips combining characters (diacritics)
    nfd = unicodedata.normalize("NFD", name)
    name = "".join(c for c in nfd if unicodedata.category(c) != "Mn")
    return re.sub(r"\s+", " ", name)


# ── Levenshtein similarity ───────────────────────────────────────────────────

def levenshtein_similarity(s1: str, s2: str) -> float:
    """Return 0.0 (completely different) to 1.0 (identical)."""
    m, n = len(s1), len(s2)
    if m == 0 and n == 0:
        return 1.0
    if m == 0 or n == 0:
        return 0.0
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev, dp[0] = dp[0], i
        for j in range(1, n + 1):
            temp = dp[j]
            dp[j] = prev if s1[i - 1] == s2[j - 1] else 1 + min(prev, dp[j], dp[j - 1])
            prev = temp
    return 1.0 - dp[n] / max(m, n)


# ── Main orchestrator ────────────────────────────────────────────────────────

def run_detection(
    *,
    trigger: str,
    triggered_by=None,
    batch_id=None,
    fuzzy_threshold: float = DEFAULT_FUZZY_THRESHOLD,
) -> RuleRun:
    """Execute a full detection run: duplicates + active rules.

    Returns the completed RuleRun record.
    """
    run = RuleRun.objects.create(
        trigger=trigger,
        triggered_by=triggered_by,
        batch_id=batch_id,
    )
    try:
        flags_count, records_scanned, rules_evaluated = _run_detection(
            run=run,
            batch_id=batch_id,
            fuzzy_threshold=fuzzy_threshold,
        )
        run.records_scanned = records_scanned
        run.rules_evaluated = rules_evaluated
        run.flags_created = flags_count
        run.status = RuleRun.STATUS_COMPLETED
        run.run_finished_at = timezone.now()
        run.save()
        logger.info(
            "Detection run %s completed: %d records, %d rules, %d flags",
            run.id, records_scanned, rules_evaluated, flags_count,
        )
    except Exception as exc:
        run.status = RuleRun.STATUS_FAILED
        run.error_message = str(exc)
        run.run_finished_at = timezone.now()
        run.save()
        logger.exception("Detection run %s failed: %s", run.id, exc)
        raise

    return run


def _run_detection(*, run: RuleRun, batch_id=None, fuzzy_threshold: float) -> tuple[int, int, int]:
    """Inner detection logic. Returns (flags_created, records_scanned, rules_evaluated)."""
    flags_created = 0
    rules_evaluated = 0

    # Scope: for post-ingest runs, only scan the specific batch; for others, all active
    qs = Credential.objects.filter(status=Credential.STATUS_ACTIVE)
    if batch_id:
        qs = qs.filter(batch_id=batch_id)

    credentials = list(qs.only("id", "credential_ref", "institution_id", "candidate_id",
                                "payload", "batch_id"))
    records_scanned = len(credentials)

    # 1. Duplicate credential usage (EVS-F05-02)
    flags_created += _detect_duplicate_credentials(credentials, run)

    # 2. Duplicate graduate index — exact match (EVS-F05-03)
    flags_created += _detect_duplicate_index_exact(credentials, run)

    # 3. Fuzzy identity match on (name + DOB + institution) (EVS-F05-03)
    flags_created += _detect_duplicate_index_fuzzy(credentials, run, threshold=fuzzy_threshold)

    # 4. Metadata anomaly rules (EVS-F05-04)
    active_rules = list(RuleDefinition.objects.filter(
        enabled=True,
        deprecated_at__isnull=True,
        effective_from__lte=timezone.now(),
    ))
    rules_evaluated = len(active_rules)
    for rule in active_rules:
        flags_created += _evaluate_rule(credentials, rule, run)

    return flags_created, records_scanned, rules_evaluated


def _detect_duplicate_credentials(credentials: list, run: RuleRun) -> int:
    """Find Credential IDs that appear more than once (cross-record duplicate usage)."""
    by_uuid: dict[str, list] = defaultdict(list)
    for cred in credentials:
        # Check payload for any claim of another credential's UUID
        payload = cred.payload or {}
        ref_id = payload.get("referenced_credential_id") or payload.get("prior_credential_id")
        if ref_id:
            by_uuid[str(ref_id)].append(str(cred.id))
    # Also look for credentials with the same hash (exact duplicate submissions)
    seen_refs: dict[str, list] = defaultdict(list)
    for cred in credentials:
        seen_refs[cred.credential_ref[:30]].append(str(cred.id))

    created = 0
    for ref, cred_ids in by_uuid.items():
        if len(cred_ids) >= 2:
            created += _create_flag(
                flag_type=FraudFlag.FLAG_DUPLICATE_CREDENTIAL,
                credential_ids=cred_ids,
                severity=FraudFlag.SEVERITY_HIGH,
                run=run,
                evidence={"duplicate_ref": ref, "credential_ids": cred_ids},
            )
    return created


def _detect_duplicate_index_exact(credentials: list, run: RuleRun) -> int:
    """Exact match on graduate_index_number — strongest signal, High severity."""
    by_index: dict[str, list] = defaultdict(list)
    for cred in credentials:
        idx = (cred.payload or {}).get("graduate_index_number", "").strip().upper()
        if idx:
            by_index[idx].append(str(cred.id))

    created = 0
    for idx, cred_ids in by_index.items():
        if len(cred_ids) >= 2:
            payloads = {str(c.id): c.payload for c in credentials if str(c.id) in cred_ids}
            diff = _compute_payload_diff(list(payloads.values()))
            created += _create_flag(
                flag_type=FraudFlag.FLAG_DUPLICATE_INDEX,
                credential_ids=cred_ids,
                severity=FraudFlag.SEVERITY_HIGH,
                run=run,
                evidence={"graduate_index_number": idx, "field_diff": diff},
            )
    return created


def _detect_duplicate_index_fuzzy(
    credentials: list, run: RuleRun, threshold: float
) -> int:
    """Fuzzy match on (name + DOB + institution_code) — Levenshtein on name."""
    if not FUZZY_THRESHOLD_MIN <= threshold <= FUZZY_THRESHOLD_MAX:
        threshold = DEFAULT_FUZZY_THRESHOLD

    # Group by (dob, institution_code) first to reduce O(n²) comparisons
    groups: dict[tuple, list] = defaultdict(list)
    for cred in credentials:
        payload = cred.payload or {}
        dob = payload.get("date_of_birth", "")
        inst = payload.get("institution_code", "") or str(cred.institution_id)
        groups[(dob, inst)].append(cred)

    created = 0
    for (dob, inst), group in groups.items():
        if len(group) < 2 or not dob:
            continue
        # O(n²) within each group — groups are usually small
        checked: set[frozenset] = set()
        for i, a in enumerate(group):
            name_a = normalise_name((a.payload or {}).get("full_name", ""))
            for b in group[i + 1:]:
                pair = frozenset([str(a.id), str(b.id)])
                if pair in checked:
                    continue
                checked.add(pair)
                name_b = normalise_name((b.payload or {}).get("full_name", ""))
                sim = levenshtein_similarity(name_a, name_b)
                if sim >= threshold:
                    created += _create_flag(
                        flag_type=FraudFlag.FLAG_FUZZY_IDENTITY,
                        credential_ids=[str(a.id), str(b.id)],
                        severity=FraudFlag.SEVERITY_MEDIUM,
                        run=run,
                        evidence={
                            "name_a": name_a, "name_b": name_b,
                            "similarity": round(sim, 4),
                            "dob": dob, "institution_code": inst,
                        },
                        similarity_score=sim,
                    )
    return created


def _evaluate_rule(credentials: list, rule: RuleDefinition, run: RuleRun) -> int:
    """Evaluate a single rule against all credentials. Returns count of new flags."""
    created = 0
    for cred in credentials:
        try:
            if _engine.evaluate(rule.predicate_json, cred.payload or {}):
                created += _create_flag(
                    flag_type=FraudFlag.FLAG_RULE_MATCH,
                    credential_ids=[str(cred.id)],
                    severity=rule.severity_default,
                    run=run,
                    rule=rule,
                    evidence={"rule_id": str(rule.id), "rule_name": rule.name,
                               "credential_ref": cred.credential_ref},
                )
        except _engine.PredicateError as exc:
            logger.warning("Rule %s predicate error on %s: %s", rule.id, cred.id, exc)
    return created


# ── Flag creation ────────────────────────────────────────────────────────────

def _create_flag(
    *,
    flag_type: str,
    credential_ids: list[str],
    severity: str,
    run: RuleRun,
    evidence: dict,
    rule: RuleDefinition | None = None,
    similarity_score: float | None = None,
) -> int:
    """Create a FraudFlag if no identical flag is already open. Returns 1 or 0."""
    # Idempotency: skip if an identical open flag already exists for the same credentials
    existing = FraudFlag.objects.filter(
        flag_type=flag_type,
        status__in=[FraudFlag.STATUS_NEW, FraudFlag.STATUS_UNDER_INVESTIGATION],
    )
    if rule:
        existing = existing.filter(rule=rule)
    for flag in existing:
        if set(flag.credential_ids) == set(credential_ids):
            return 0

    with transaction.atomic():
        flag = FraudFlag.objects.create(
            flag_type=flag_type,
            credential_ids=credential_ids,
            severity=severity,
            run=run,
            rule=rule,
            evidence_payload=evidence,
            fuzzy_similarity_score=similarity_score,
        )
        FlagAction.objects.create(
            flag=flag,
            action=FlagAction.ACTION_CREATED,
            payload={"trigger": run.trigger, "severity": severity},
        )
        _anchor_to_audit(flag, "FRAUD_FLAG_CREATED")
    return 1


def _anchor_to_audit(flag: FraudFlag, action: str) -> None:
    """Write a tamper-evident AuditEvent and anchor to System 22."""
    try:
        from apps.audit.models import AuditEvent
        event = AuditEvent.record(
            action=action,
            entity_type="FraudFlag",
            entity_id=str(flag.id),
            actor_id=None,
            new_state={"severity": flag.severity, "flag_type": flag.flag_type, "status": flag.status},
            old_state={},
        )
        if event:
            flag.audit_hash = event.sha256_hash if hasattr(event, "sha256_hash") else ""
            flag.save(update_fields=["audit_hash"])
    except Exception as exc:
        logger.warning("Failed to anchor flag %s to audit: %s", flag.id, exc)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _compute_payload_diff(payloads: list[dict]) -> dict:
    """Highlight fields that differ across a set of payloads."""
    if len(payloads) < 2:
        return {}
    all_keys = set().union(*(p.keys() for p in payloads))
    diff = {}
    for key in sorted(all_keys):
        values = [p.get(key) for p in payloads]
        if len(set(str(v) for v in values)) > 1:
            diff[key] = values
    return diff


def resolve_flag(
    *,
    flag: FraudFlag,
    new_status: str,
    justification: str,
    resolver_id,
) -> FraudFlag:
    """Resolve a flag. Confirmed Fraud triggers revocation + watchlist."""
    words = len(justification.split())
    if words < 30:
        from shared.exceptions import error_response
        raise ValueError(f"Justification must be ≥30 words (got {words}).")

    old_status = flag.status
    flag.status = new_status
    flag.resolution_justification = justification
    flag.resolver_id = resolver_id
    flag.resolved_at = timezone.now()

    with transaction.atomic():
        flag.save()
        FlagAction.objects.create(
            flag=flag,
            actor_user_id=resolver_id,
            action=FlagAction.ACTION_RESOLVED,
            payload={
                "old_status": old_status,
                "new_status": new_status,
                "justification_word_count": words,
            },
        )

    if new_status == FraudFlag.STATUS_CONFIRMED_FRAUD:
        _trigger_revocations(flag, resolver_id)
        _add_to_watchlist(flag, resolver_id)

    _anchor_to_audit(flag, "FRAUD_FLAG_RESOLVED")
    return flag


def _trigger_revocations(flag: FraudFlag, resolver_id) -> None:
    """Revoke all affected credentials; already-revoked ones are no-ops."""
    for cred_id in flag.credential_ids:
        try:
            cred = Credential.objects.get(pk=cred_id)
            if cred.status == Credential.STATUS_REVOKED:
                logger.info("Credential %s already revoked — no-op", cred_id)
                continue
            cred.status = Credential.STATUS_REVOKED
            cred.revoked_at = timezone.now()
            cred.revoke_reason = f"Confirmed Fraud — flag {flag.id}"
            cred.revoked_by = resolver_id
            cred.save()
        except Credential.DoesNotExist:
            logger.warning("Credential %s not found for revocation", cred_id)


def _add_to_watchlist(flag: FraudFlag, resolver_id) -> None:
    """Add all applicants in the flag to the active watchlist."""
    from .models import WatchlistEntry
    for applicant_id in flag.applicant_ids:
        WatchlistEntry.objects.get_or_create(
            applicant_id=applicant_id,
            reason_flag=flag,
            defaults={"added_by": resolver_id},
        )
