"""HSM API views — JWKS endpoint (public) + sign endpoint (internal)."""
import base64
import logging
import math

from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from shared.exceptions import HsmUnavailable, error_response
from shared.permissions import IsServiceAccount

from .models import HsmKey
from .service import sign_payload

logger = logging.getLogger(__name__)


class JwksView(APIView):
    """GET /v1/hsm/jwks — public JWKS for QR JWT verification."""

    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request):
        keys = HsmKey.objects.filter(is_active=True)
        jwks = {"keys": [_to_jwk(k) for k in keys if k.public_key_pem]}
        return Response(jwks)


class SignView(APIView):
    """POST /v1/hsm/sign — internal signing endpoint for trusted services."""

    permission_classes = [IsServiceAccount]

    def post(self, request):
        purpose = request.data.get("purpose")
        payload = request.data.get("payload")
        if not purpose or payload is None:
            return error_response("Both 'purpose' and 'payload' are required.", status=400)
        if not isinstance(payload, dict):
            return error_response("'payload' must be a JSON object.", status=400)

        try:
            result = sign_payload(purpose=purpose, payload=payload)
        except NotImplementedError as exc:
            raise HsmUnavailable(str(exc))
        except ValueError as exc:
            return error_response(str(exc), status=400)
        except Exception as exc:
            logger.error("hsm.sign_failed purpose=%s err=%s", purpose, exc)
            raise HsmUnavailable("HSM signing failed.")

        return Response(result)


# ── helpers ───────────────────────────────────────────────────────────────────

def _to_jwk(key: HsmKey) -> dict:
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

        pub = load_pem_public_key(key.public_key_pem.encode())

        if isinstance(pub, EllipticCurvePublicKey):
            nums = pub.public_numbers()

            def _b64(n, length=32):
                return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

            return {
                "kty": "EC", "kid": key.kid, "alg": key.algorithm, "use": "sig",
                "crv": "P-256", "x": _b64(nums.x), "y": _b64(nums.y),
            }

        if isinstance(pub, RSAPublicKey):
            nums = pub.public_numbers()

            def _b64url(n):
                return base64.urlsafe_b64encode(
                    n.to_bytes(math.ceil(n.bit_length() / 8), "big")
                ).rstrip(b"=").decode()

            return {
                "kty": "RSA", "kid": key.kid, "alg": key.algorithm, "use": "sig",
                "n": _b64url(nums.n), "e": _b64url(nums.e),
            }

    except Exception as exc:
        logger.warning("jwks.parse_failed kid=%s err=%s", key.kid, exc)

    return {"kty": "oct", "kid": key.kid, "alg": key.algorithm, "use": "sig"}
