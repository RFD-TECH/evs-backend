"""Canonical JSON + SHA-256 for credential payloads.

Canonical form (SRS §4.3):
  - Keys sorted lexicographically (json.dumps sort_keys=True)
  - No extra whitespace (separators=(',', ':'))
  - UTF-8 NFC normalisation on all string values
  - Null/empty values elided (None, "", [], {} removed)
  - Floats converted to fixed-point decimal strings (avoids float repr divergence)
  - Encoding: UTF-8
  - Integrity comparison: constant-time via hmac.compare_digest
"""
import hashlib
import hmac
import json
import unicodedata
from decimal import Decimal, ROUND_DOWN


def canonical_json(payload: dict) -> str:
    """Return the canonical JSON string for *payload*."""
    return json.dumps(_normalize(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_of_canonical(payload: dict) -> str:
    """Return the hex SHA-256 of the canonical JSON bytes."""
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def hashes_equal(a: str, b: str) -> bool:
    """Constant-time comparison of two hex hash strings."""
    return hmac.compare_digest(a.encode(), b.encode())


def _normalize(obj):
    if obj is None:
        return None
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float):
        # Fixed-point to avoid float repr divergence across platforms.
        return str(Decimal(str(obj)).quantize(Decimal("0.000001"), rounding=ROUND_DOWN))
    if isinstance(obj, int):
        return obj
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            nk = _normalize(k)
            nv = _normalize(v)
            if _is_empty(nv):
                continue
            result[nk] = nv
        return result
    if isinstance(obj, list):
        result = [_normalize(item) for item in obj]
        return [item for item in result if not _is_empty(item)]
    return obj


def _is_empty(value) -> bool:
    if value is None:
        return True
    if isinstance(value, str) and value == "":
        return True
    if isinstance(value, dict) and len(value) == 0:
        return True
    if isinstance(value, list) and len(value) == 0:
        return True
    return False
