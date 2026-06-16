"""EVS verification API views — QR scan channel (Phase 3)."""
import hashlib
import logging

from django.conf import settings
from django.shortcuts import get_object_or_404
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet

from shared.exceptions import error_response
from shared.pagination import StandardResultsPagination
from shared.permissions import check_permission

from .models import VerificationSession
from .serializers import VerificationSessionSerializer
from .service import verify_credential

logger = logging.getLogger(__name__)


class PublicVerifyView(APIView):
    """GET /v1/verify/{credential_id}?token=<jwt>

    Public — no authentication required. Phase 3 QR scan path.
    Target response time: ≤2000 ms (EVS-P01).
    """

    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request, credential_id):
        if not getattr(settings, "EVS_QR_VERIFICATION_ENABLED", True):
            return error_response("QR verification is temporarily unavailable.", status=503)

        token = request.query_params.get("token", "").strip()
        if not token:
            return error_response("'token' query parameter is required.", status=400)

        ip = _get_client_ip(request)
        result = verify_credential(
            credential_id=str(credential_id),
            token=token,
            ip=ip,
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            verifier_id=getattr(getattr(request, "user", None), "id", None),
            channel=request.query_params.get("channel", "qr_scan"),
            device_fingerprint=request.query_params.get("device_fingerprint", ""),
        )
        http_status = 200 if result["result"] == "verified" else _result_to_http(result["result"])
        return Response(result, status=http_status)


class ResultRetrieveView(APIView):
    """GET /v1/verify/results/{result_id}

    Retrieve a past verification result by its stable result_id UUID.
    Requires audit:read permission.
    """

    def get(self, request, result_id):
        if not check_permission(request, "audit:read"):
            return error_response("Forbidden", status=403)
        session = get_object_or_404(VerificationSession, result_id=result_id)
        return Response(VerificationSessionSerializer(session).data)


class VerificationSessionViewSet(GenericViewSet):
    """Authenticated query over past QR verification sessions."""

    pagination_class = StandardResultsPagination

    def get_queryset(self):
        return VerificationSession.objects.order_by("-created_at")

    def list(self, request):
        if not check_permission(request, "audit:read"):
            return error_response("Forbidden", status=403)

        qs = self.get_queryset()
        if cid := request.query_params.get("credential_id"):
            qs = qs.filter(credential_id_claimed=cid)
        if result := request.query_params.get("result"):
            qs = qs.filter(result=result)
        if channel := request.query_params.get("channel"):
            qs = qs.filter(channel=channel)

        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(VerificationSessionSerializer(page, many=True).data)
        return Response(VerificationSessionSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "audit:read"):
            return error_response("Forbidden", status=403)
        session = get_object_or_404(self.get_queryset(), pk=pk)
        return Response(VerificationSessionSerializer(session).data)


def _get_client_ip(request) -> str:
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def _result_to_http(result: str) -> int:
    return {
        "revoked": 410,
        "quarantined": 409,
        "not_found": 404,
        "tampered": 422,
        "token_invalid": 401,
        "token_expired": 401,
    }.get(result, 400)
