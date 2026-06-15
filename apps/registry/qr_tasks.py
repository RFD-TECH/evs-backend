"""QR JWT signing task — runs in high-priority queue after credential registration."""
import logging

from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(name="apps.registry.qr_tasks.sign_qr_jwt", queue="high-priority", max_retries=3)
def sign_qr_jwt(*, credential_id: str):
    """Sign a QR JWT for credential *credential_id* and persist it."""
    from django.conf import settings

    from apps.registry.models import Credential
    from apps.hsm.service import sign_payload

    try:
        cred = Credential.objects.get(pk=credential_id)
    except Credential.DoesNotExist:
        logger.error("sign_qr_jwt: credential not found id=%s", credential_id)
        return

    try:
        result = sign_payload(
            purpose="qr_jwt_sign",
            payload={
                "sub": str(cred.id),
                "ref": cred.credential_ref,
                "sha": cred.sha256_hash,
                "iss": getattr(settings, "EVS_QR_JWT_ISSUER", "evs.clet.gov.gh"),
            },
        )
        token = result["token"]
        qr_url = f"{cred.qr_url}?token={token}"
        Credential.objects.filter(pk=credential_id).update(
            qr_payload=token, qr_url=qr_url,
        )
        logger.info("sign_qr_jwt: signed credential=%s kid=%s", credential_id, result.get("kid"))
    except Exception as exc:
        logger.error("sign_qr_jwt: failed credential=%s err=%s", credential_id, exc)
        raise  # Celery retry
