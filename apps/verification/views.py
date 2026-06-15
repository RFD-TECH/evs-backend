"""EVS verification API views — QR scan + PDF + Uploaded-QR + admin."""
import logging

from django.conf import settings
from django.shortcuts import get_object_or_404
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet

from shared.exceptions import error_response, success_response
from shared.pagination import StandardResultsPagination
from shared.permissions import check_permission

from .models import DocumentVaultObject, TrustAnchor, VerificationSession
from .serializers import (
    DocumentVaultObjectSerializer, TrustAnchorCreateSerializer,
    TrustAnchorSerializer, VerificationSessionSerializer,
)
from .service import verify_credential

logger = logging.getLogger(__name__)

ALLOWED_PDF_MIME = {"application/pdf"}
ALLOWED_QR_MIME = {"application/pdf", "image/png", "image/jpeg", "image/webp"}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB


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
        )
        http_status = 200 if result["result"] == "verified" else _result_to_http(result["result"])
        return Response(result, status=http_status)


class PdfVerifyView(APIView):
    """POST /v1/verify/pdf — submit a signed PDF certificate for verification (F06)."""

    parser_classes = [MultiPartParser]

    def post(self, request):
        if not check_permission(request, "credential:read"):
            return error_response("Forbidden", status=403)

        file_obj = request.FILES.get("file")
        if file_obj is None:
            return error_response("'file' field is required.", status=400)
        if file_obj.content_type not in ALLOWED_PDF_MIME:
            return error_response("Only PDF files are accepted.", status=415)
        if file_obj.size > MAX_UPLOAD_BYTES:
            return error_response("File exceeds the 10 MB limit.", status=413)

        file_bytes = file_obj.read()

        from .pdf_service import verify_pdf
        result = verify_pdf(
            file_bytes=file_bytes,
            ip=_get_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            verifier_id=getattr(request.user, "id", None),
        )

        result.pop("_session_id", None)
        http_status = 200 if result["result"] == "verified" else _result_to_http(result["result"])
        return Response(result, status=http_status)


class UploadedQrVerifyView(APIView):
    """POST /v1/verify/uploaded-qr — decode QR from uploaded image or PDF (F07)."""

    parser_classes = [MultiPartParser]

    def post(self, request):
        if not check_permission(request, "credential:read"):
            return error_response("Forbidden", status=403)

        file_obj = request.FILES.get("file")
        if file_obj is None:
            return error_response("'file' field is required.", status=400)
        if file_obj.content_type not in ALLOWED_QR_MIME:
            return error_response(
                "Accepted types: PDF, PNG, JPEG.", status=415
            )
        if file_obj.size > MAX_UPLOAD_BYTES:
            return error_response("File exceeds the 10 MB limit.", status=413)

        file_bytes = file_obj.read()
        from .qr_upload_service import verify_uploaded_qr
        result = verify_uploaded_qr(
            file_bytes=file_bytes,
            mime_type=file_obj.content_type,
            ip=_get_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            verifier_id=getattr(request.user, "id", None),
        )
        http_status = 200 if result["result"] == "verified" else _result_to_http(result["result"])
        return Response(result, status=http_status)


class VerificationSessionViewSet(GenericViewSet):
    """Authenticated query over past verification sessions (auditor / registrar)."""

    pagination_class = StandardResultsPagination

    def get_queryset(self):
        return VerificationSession.objects.order_by("-created_at")

    def list(self, request):
        if not check_permission(request, "audit:read"):
            return error_response("Forbidden", status=403)

        qs = self.get_queryset()
        if cid := request.query_params.get("credential_id"):
            qs = qs.filter(credential_id_claimed=cid)
        if ch := request.query_params.get("channel"):
            qs = qs.filter(channel=ch)
        if result := request.query_params.get("result"):
            qs = qs.filter(result=result)
        if sha := request.query_params.get("file_sha256"):
            qs = qs.filter(file_sha256=sha)

        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(VerificationSessionSerializer(page, many=True).data)
        return Response(VerificationSessionSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "audit:read"):
            return error_response("Forbidden", status=403)
        session = get_object_or_404(self.get_queryset(), pk=pk)
        return Response(VerificationSessionSerializer(session).data)


class TrustAnchorViewSet(GenericViewSet):
    """Trust Anchor administration — F06-03 (Administrator only)."""

    def list(self, request):
        if not check_permission(request, "trust_anchor:manage"):
            return error_response("Forbidden", status=403)
        anchors = TrustAnchor.objects.all()
        return Response(TrustAnchorSerializer(anchors, many=True).data)

    def create(self, request):
        if not check_permission(request, "trust_anchor:manage"):
            return error_response("Forbidden", status=403)
        serializer = TrustAnchorCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)

        anchor = serializer.save(
            added_by=getattr(request.user, "keycloak_sub", None)
        )
        _audit_trust_anchor("TRUST_ANCHOR_ADDED", anchor, request)
        return success_response(TrustAnchorSerializer(anchor).data)

    def destroy(self, request, pk=None):
        if not check_permission(request, "trust_anchor:manage"):
            return error_response("Forbidden", status=403)
        anchor = get_object_or_404(TrustAnchor, pk=pk)
        anchor.status = TrustAnchor.STATUS_REVOKED
        anchor.save(update_fields=["status", "updated_at"])
        _audit_trust_anchor("TRUST_ANCHOR_REVOKED", anchor, request)
        return success_response({"status": "revoked"})


class DocumentVaultViewSet(GenericViewSet):
    """Document vault browser (Registrar / Auditor)."""

    pagination_class = StandardResultsPagination

    def get_queryset(self):
        return DocumentVaultObject.objects.order_by("-uploaded_at")

    def list(self, request):
        if not check_permission(request, "vault:read"):
            return error_response("Forbidden", status=403)
        qs = self.get_queryset()
        if sha := request.query_params.get("sha256"):
            qs = qs.filter(sha256=sha)
        if tampered := request.query_params.get("tamper_flag"):
            qs = qs.filter(tamper_flag=tampered.lower() == "true")
        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(DocumentVaultObjectSerializer(page, many=True).data)
        return Response(DocumentVaultObjectSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "vault:read"):
            return error_response("Forbidden", status=403)
        obj = get_object_or_404(self.get_queryset(), pk=pk)
        return Response(DocumentVaultObjectSerializer(obj).data)


# ── helpers ───────────────────────────────────────────────────────────────────

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
        "invalid_signature": 422,
        "untrusted_issuer": 422,
        "invalid_qr": 422,
    }.get(result, 400)


def _audit_trust_anchor(action: str, anchor, request):
    try:
        from apps.audit.models import AuditEvent
        AuditEvent.record(
            action=action,
            entity_type="TrustAnchor",
            entity_id=str(anchor.id),
            actor_id=getattr(request.user, "keycloak_sub", None),
            new_state={"ca_name": anchor.ca_name, "status": anchor.status},
            old_state={},
        )
    except Exception:
        pass
