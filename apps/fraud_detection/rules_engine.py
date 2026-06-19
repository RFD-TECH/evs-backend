"""Configurable rules engine — predicate evaluation and dry-run (EVS-F05-04).

Predicate JSON format:
  Composite:  {"op": "and"|"or", "conditions": [...]}
  Negation:   {"op": "not", "condition": {...}}
  Leaf:       {"op": "eq"|"neq"|"lt"|"lte"|"gt"|"gte", "field": "...", "value": ...}
              {"op": "regex", "field": "...", "value": "<pattern>"}
              {"op": "in"|"not_in", "field": "...", "value": [...]}
              {"op": "date_diff_years_lt"|"date_diff_years_gt",
               "left_field": "...", "right_field": "...|today", "years": N}

Special computed fields (not in payload directly):
  "age_at_graduation" — (award_date - date_of_birth) in whole years
"""
from __future__ import annotations

import logging
import re
import unicodedata
from datetime import date
from typing import Any

logger = logging.getLogger(__name__)

LEAF_OPS = {"eq", "neq", "lt", "lte", "gt", "gte", "regex", "in", "not_in"}
DATE_OPS = {"date_diff_years_lt", "date_diff_years_gt", "date_diff_years_lte", "date_diff_years_gte"}
COMPOSITE_OPS = {"and", "or", "not"}
ALL_OPS = LEAF_OPS | DATE_OPS | COMPOSITE_OPS

FUZZY_THRESHOLD_MIN = 0.5
FUZZY_THRESHOLD_MAX = 0.99


class PredicateError(ValueError):
    """Raised when a predicate is structurally invalid."""


def validate_predicate(predicate: dict) -> list[str]:
    """Return a list of error strings; empty list means valid."""
    errors: list[str] = []
    _validate_node(predicate, errors, path="root")
    return errors


def _validate_node(node: Any, errors: list[str], path: str) -> None:
    if not isinstance(node, dict):
        errors.append(f"{path}: node must be a dict, got {type(node).__name__}")
        return

    op = node.get("op")
    if op not in ALL_OPS:
        errors.append(f"{path}.op: unknown op '{op}'. Valid: {sorted(ALL_OPS)}")
        return

    if op == "and" or op == "or":
        conditions = node.get("conditions", [])
        if not isinstance(conditions, list) or len(conditions) < 2:
            errors.append(f"{path}.conditions: '{op}' requires a list of ≥2 conditions")
        else:
            for i, cond in enumerate(conditions):
                _validate_node(cond, errors, f"{path}.conditions[{i}]")

    elif op == "not":
        cond = node.get("condition")
        if cond is None:
            errors.append(f"{path}.condition: 'not' requires a 'condition' key")
        else:
            _validate_node(cond, errors, f"{path}.condition")

    elif op in DATE_OPS:
        if "left_field" not in node:
            errors.append(f"{path}.left_field: required for '{op}'")
        if "right_field" not in node:
            errors.append(f"{path}.right_field: required for '{op}'")
        if "years" not in node:
            errors.append(f"{path}.years: required for '{op}'")
        elif not isinstance(node["years"], (int, float)) or node["years"] < 0:
            errors.append(f"{path}.years: must be a non-negative number")

    else:  # LEAF_OPS
        if "field" not in node:
            errors.append(f"{path}.field: required for '{op}'")
        if op != "regex" and "value" not in node:
            errors.append(f"{path}.value: required for '{op}'")
        if op == "regex":
            pattern = node.get("value", "")
            try:
                re.compile(pattern)
            except re.error as exc:
                errors.append(f"{path}.value: invalid regex — {exc}")
        if op in ("in", "not_in") and not isinstance(node.get("value"), list):
            errors.append(f"{path}.value: '{op}' requires a list value")


def evaluate(predicate: dict, credential_data: dict) -> bool:
    """Evaluate a predicate against a credential payload dict.

    Returns True when the predicate matches (the credential is anomalous).
    Raises PredicateError on structural failures.
    """
    try:
        return _eval_node(predicate, credential_data)
    except PredicateError:
        raise
    except Exception as exc:
        raise PredicateError(f"Evaluation error: {exc}") from exc


def _eval_node(node: dict, data: dict) -> bool:
    op = node["op"]

    if op == "and":
        return all(_eval_node(c, data) for c in node["conditions"])
    if op == "or":
        return any(_eval_node(c, data) for c in node["conditions"])
    if op == "not":
        return not _eval_node(node["condition"], data)

    if op in DATE_OPS:
        return _eval_date_op(node, data)

    # Leaf ops
    field = node["field"]
    left = _resolve(data, field)
    right = node.get("value")

    if op == "eq":
        return left == right
    if op == "neq":
        return left != right
    if op in ("lt", "lte", "gt", "gte"):
        if left is None or right is None:
            return False
        if op == "lt":
            return left < right
        if op == "lte":
            return left <= right
        if op == "gt":
            return left > right
        return left >= right
    if op == "regex":
        return bool(re.search(str(node.get("value", "")), str(left or "")))
    if op == "in":
        return left in (right or [])
    if op == "not_in":
        return left not in (right or [])

    return False


def _eval_date_op(node: dict, data: dict) -> bool:
    left_field = node["left_field"]
    right_field = node["right_field"]
    years = int(node["years"])

    left = _resolve_date(data, left_field)
    right = _resolve_date(data, right_field)
    if left is None or right is None:
        return False

    diff_years = abs((right - left).days) // 365
    op = node["op"]
    if op == "date_diff_years_lt":
        return diff_years < years
    if op == "date_diff_years_gt":
        return diff_years > years
    if op == "date_diff_years_lte":
        return diff_years <= years
    return diff_years >= years


def _resolve(data: dict, field: str) -> Any:
    """Resolve a field, including computed fields like age_at_graduation."""
    if field == "age_at_graduation":
        dob = _resolve_date(data, "date_of_birth")
        award = _resolve_date(data, "award_date")
        if dob and award:
            return (award - dob).days // 365
        return None
    val = data.get(field)
    # Try auto-casting string dates for numeric comparisons
    if isinstance(val, str):
        try:
            return int(val)
        except ValueError:
            pass
    return val


def _resolve_date(data: dict, field_or_keyword: str) -> date | None:
    if field_or_keyword == "today":
        return date.today()
    val = data.get(field_or_keyword)
    if isinstance(val, date):
        return val
    if isinstance(val, str):
        try:
            return date.fromisoformat(val)
        except ValueError:
            return None
    return None


def dry_run(predicate: dict, sample_credentials: list[dict]) -> dict:
    """Evaluate predicate against a list of credential payload dicts.

    Returns: {matches: int, total: int, sample_matches: list[credential_ref]}
    """
    matches = []
    errors = 0
    for cred in sample_credentials:
        try:
            if evaluate(predicate, cred.get("payload", cred)):
                matches.append(cred.get("credential_ref", str(cred.get("id", ""))))
        except PredicateError:
            errors += 1
    return {
        "matches": len(matches),
        "total": len(sample_credentials),
        "evaluation_errors": errors,
        "sample_match_refs": matches[:50],
    }
