"""Canonical JSON + SHA-256 for credential payloads.

Canonical form:
  - Keys sorted lexicographically (json.dumps sort_keys=True)
  - No extra whitespace (separators=(',', ':'))
  - UTF-8 NFC normalisation on all string values
  - Encoding: UTF-8
"""
import hashlib
import json
import unicodedata


def canonical_json(payload: dict) -> str:
    """Return the canonical JSON string for *payload*."""
    return json.dumps(_normalize(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_of_canonical(payload: dict) -> str:
    """Return the hex SHA-256 of the canonical JSON bytes."""
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _normalize(obj):
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict):
        return {_normalize(k): _normalize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize(item) for item in obj]
    return obj
