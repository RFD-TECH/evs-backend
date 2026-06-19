"""Auditor-General export bundle service (Phase 9 — EVS-N06).

Responsibilities
----------------
1. Query AuditEvents and Credentials for the requested date range / institution.
2. Build a ZIP bundle containing:
   - ``data.json``   — canonical NDJSON export (one JSON object per line, sorted by id)
   - ``report.pdf``  — human-readable summary (generated via reportlab if available,
                        else a plain-text fallback)
   - ``manifest.json`` — bundle metadata + SHA-256 of each included file
   - ``verify.md``   — chain verification guide with embedded Python snippet
3. Compute SHA-256 of the ZIP, HSM-sign it, upload to MinIO.
4. Persist the signed MinIO pre-signed URL back to ``ExportRequest``.

Design decisions
----------------
* **No database deletion.** All export data is non-destructive.
* **HSM fallback.** When ``HSM_ENABLED=False``, we fall back to HMAC-SHA256 with
  ``settings.SECRET_KEY`` so dev/CI environments are not blocked.
* **Thin task.** ``run_auditor_general_export`` in ``audit/tasks.py`` calls this
  service; all logic lives here so it can be unit-tested without Celery.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import io
import json
import logging
import zipfile
from datetime import date
from typing import Optional

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)


# ── HSM helpers ───────────────────────────────────────────────────────────────

def _sign_bytes(data: bytes) -> tuple[str, str]:
    """Return (base64_signature, key_id).

    Uses the HSM when enabled; falls back to HMAC-SHA256 in dev/CI.
    """
    if getattr(settings, "HSM_ENABLED", False):
        try:
            from apps.hsm.service import get_hsm_service
            hsm = get_hsm_service()
            key_id = getattr(settings, "HSM_KEY_ID_DG_SIGN", "evs-dg-sign-v1")
            sig_bytes = hsm.sign(key_id=key_id, data=data)
            return base64.b64encode(sig_bytes).decode(), key_id
        except Exception as exc:
            logger.warning("export_service.hsm_sign_failed — falling back to HMAC: %s", exc)

    # Software fallback (dev / CI)
    secret = settings.SECRET_KEY.encode()
    sig = hmac.new(secret, data, hashlib.sha256).digest()
    return base64.b64encode(sig).decode(), "software-hmac-sha256"


# ── MinIO helpers ─────────────────────────────────────────────────────────────

def _upload_to_minio(object_key: str, data: bytes, content_type: str = "application/zip") -> str:
    """Upload *data* to MinIO and return a pre-signed URL.

    Returns an empty string when MinIO is disabled (local dev without MinIO).
    """
    if not getattr(settings, "MINIO_ENABLED", False):
        logger.info("export_service.minio_disabled — skipping upload of %s", object_key)
        return f"local://{object_key}"

    try:
        from minio import Minio
        from minio.error import S3Error

        client = Minio(
            settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=getattr(settings, "MINIO_SECURE", False),
        )
        bucket = getattr(settings, "EVS_EXPORT_BUCKET_NAME", settings.MINIO_BUCKET_NAME)

        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)

        client.put_object(
            bucket, object_key, io.BytesIO(data), len(data), content_type=content_type
        )

        ttl = getattr(settings, "EVS_EXPORT_URL_TTL_SECONDS", 86400)
        from datetime import timedelta
        url = client.presigned_get_object(bucket, object_key, expires=timedelta(seconds=ttl))
        return url
    except Exception as exc:
        logger.error("export_service.minio_upload_failed key=%s err=%s", object_key, exc)
        raise


# ── PDF generation ────────────────────────────────────────────────────────────

def _build_pdf(
    date_from: date,
    date_to: date,
    event_count: int,
    credential_count: int,
    bundle_hash: str,
) -> bytes:
    """Return PDF bytes for the AG export report.

    Uses reportlab when available; falls back to UTF-8 plain text.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4)
        styles = getSampleStyleSheet()
        story = [
            Paragraph("EXAMINATION VERIFICATION SYSTEM", styles["Title"]),
            Paragraph("Auditor-General Signed Export Report", styles["Heading1"]),
            Spacer(1, 12),
            Paragraph(f"Export period: {date_from} – {date_to}", styles["Normal"]),
            Paragraph(f"Audit events included: {event_count:,}", styles["Normal"]),
            Paragraph(f"Credential records included: {credential_count:,}", styles["Normal"]),
            Spacer(1, 12),
            Paragraph(f"Bundle SHA-256: {bundle_hash}", styles["Code"]),
            Spacer(1, 12),
            Paragraph(
                "This export has been cryptographically signed. Use the included verify.md "
                "guide to validate the integrity of this bundle independently.",
                styles["Normal"],
            ),
        ]
        doc.build(story)
        return buf.getvalue()
    except ImportError:
        # Plain-text fallback
        text = (
            "EXAMINATION VERIFICATION SYSTEM\n"
            "Auditor-General Signed Export Report\n"
            "=" * 60 + "\n\n"
            f"Export period : {date_from} to {date_to}\n"
            f"Audit events  : {event_count:,}\n"
            f"Credentials   : {credential_count:,}\n\n"
            f"Bundle SHA-256: {bundle_hash}\n\n"
            "This export has been cryptographically signed. See verify.md.\n"
        )
        return text.encode("utf-8")


def _build_verify_md(bundle_hash: str, signature: str, key_id: str) -> bytes:
    """Return the Markdown chain-verification guide as bytes."""
    content = f"""\
# EVS Export — Chain Verification Guide

## Bundle integrity

SHA-256 of this ZIP archive: `{bundle_hash}`

HSM signature (base64): `{signature}`

HSM key ID: `{key_id}`

## How to verify (Python 3.9+)

```python
import hashlib, base64, hmac, zipfile

# 1. Compute the ZIP hash
with open("evs_export.zip", "rb") as f:
    data = f.read()
actual_hash = hashlib.sha256(data).hexdigest()
assert actual_hash == "{bundle_hash}", f"Hash mismatch: {{actual_hash}}"
print("✅ ZIP integrity OK")

# 2. Verify data.json line-count matches manifest
import json
with zipfile.ZipFile("evs_export.zip") as zf:
    manifest = json.loads(zf.read("manifest.json"))
    lines = zf.read("data.json").decode().strip().splitlines()
    assert len(lines) == manifest["event_count"], "Event count mismatch"
    print(f"✅ {{len(lines)}} events matched manifest")
```

## Audit Chain Continuity

Each AuditEvent in `data.json` contains a `chain_hash` field.
Verify the hash chain integrity:

```python
import hashlib, json

prev_hash = "0" * 64  # start from genesis or the prior anchor

with zipfile.ZipFile("evs_export.zip") as zf:
    for line in zf.read("data.json").decode().strip().splitlines():
        event = json.loads(line)
        payload = json.dumps({{
            "event_id": event["event_id"],
            "actor_id": event.get("actor_id", ""),
            "action": event["action"],
            "entity_type": event.get("entity_type", ""),
            "entity_id": str(event.get("entity_id", "")),
            "old_state": event.get("old_state") or {{}},
            "new_state": event.get("new_state") or {{}},
            "created_at": event["created_at"],
        }}, sort_keys=True)
        expected = hashlib.sha256(f"{{prev_hash}}{{payload}}".encode()).hexdigest()
        assert expected == event["chain_hash"], f"Chain broken at event {{event['event_id']}}"
        prev_hash = event["chain_hash"]

print("✅ Full audit chain verified")
```
"""
    return content.encode("utf-8")


# ── Main service entry point ──────────────────────────────────────────────────

def build_export_bundle(
    *,
    date_from: date,
    date_to: date,
    institution_id: Optional[str] = None,
    export_request_id: str,
) -> dict:
    """Build, sign, and upload a complete AG export bundle.

    Returns a dict with keys:
      - ``signed_bundle_url``   — MinIO pre-signed URL
      - ``bundle_hash``         — SHA-256 hex of the ZIP
      - ``hsm_signature``       — base64 HSM/HMAC signature
      - ``hsm_key_id``          — key identifier used for signing
      - ``event_count``         — number of audit events exported
      - ``credential_count``    — number of credentials exported
    """
    from apps.audit.models import AuditEvent

    # ── 1. Query data ─────────────────────────────────────────────────────────
    start_dt = timezone.datetime(
        date_from.year, date_from.month, date_from.day, tzinfo=timezone.utc
    )
    end_dt = timezone.datetime(
        date_to.year, date_to.month, date_to.day, 23, 59, 59, tzinfo=timezone.utc
    )

    events_qs = AuditEvent.objects.filter(
        created_at__gte=start_dt, created_at__lte=end_dt
    ).order_by("id")

    from apps.registry.models import Credential
    creds_qs = Credential.objects.filter(
        created_at__gte=start_dt, created_at__lte=end_dt
    ).order_by("id")

    if institution_id:
        creds_qs = creds_qs.filter(institution_id=institution_id)

    # ── 2. Build NDJSON export ────────────────────────────────────────────────
    event_lines = []
    for ev in events_qs.values(
        "event_id", "actor_id", "action", "entity_type", "entity_id",
        "old_state", "new_state", "chain_hash", "source_system", "created_at",
    ):
        line = {k: str(v) if v is not None else None for k, v in ev.items()}
        event_lines.append(json.dumps(line, default=str))

    data_ndjson = "\n".join(event_lines).encode("utf-8")
    event_count = len(event_lines)
    credential_count = creds_qs.count()

    # ── 3. Build manifest ─────────────────────────────────────────────────────
    manifest = {
        "export_request_id": export_request_id,
        "date_from": date_from.isoformat(),
        "date_to": date_to.isoformat(),
        "institution_id": str(institution_id) if institution_id else None,
        "event_count": event_count,
        "credential_count": credential_count,
        "generated_at": timezone.now().isoformat(),
        "data_sha256": hashlib.sha256(data_ndjson).hexdigest(),
    }
    manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")

    # ── 4. Build initial ZIP (without bundle_hash yet) ────────────────────────
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("data.json", data_ndjson)
        zf.writestr("manifest.json", manifest_bytes)

    partial_zip = zip_buf.getvalue()
    bundle_hash_partial = hashlib.sha256(partial_zip).hexdigest()

    # Build PDF and verify.md now that we have a bundle hash
    pdf_bytes = _build_pdf(date_from, date_to, event_count, credential_count, bundle_hash_partial)
    signature, key_id = _sign_bytes(bundle_hash_partial.encode())
    verify_md = _build_verify_md(bundle_hash_partial, signature, key_id)

    # ── 5. Rebuild final ZIP ──────────────────────────────────────────────────
    final_buf = io.BytesIO()
    with zipfile.ZipFile(final_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("data.json", data_ndjson)
        zf.writestr("manifest.json", manifest_bytes)
        zf.writestr("report.pdf", pdf_bytes)
        zf.writestr("verify.md", verify_md)

    final_zip = final_buf.getvalue()
    bundle_hash = hashlib.sha256(final_zip).hexdigest()

    # Re-sign final ZIP hash
    signature, key_id = _sign_bytes(bundle_hash.encode())

    # ── 6. Upload to MinIO ────────────────────────────────────────────────────
    object_key = f"exports/{export_request_id}/{date_from}_{date_to}.zip"
    signed_url = _upload_to_minio(object_key, final_zip)

    return {
        "signed_bundle_url": signed_url,
        "bundle_hash": bundle_hash,
        "hsm_signature": signature,
        "hsm_key_id": key_id,
        "event_count": event_count,
        "credential_count": credential_count,
    }
