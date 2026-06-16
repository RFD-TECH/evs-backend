"""EVS registry API views."""
import hashlib
import logging

from django.shortcuts import get_object_or_404
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet

from shared.exceptions import error_response, success_response
from shared.pagination import StandardResultsPagination
from shared.permissions import check_permission

from .models import BatchIngest, Credential, CredentialSchemaVersion, RevocationRecord
from .serializers import (
    BatchIngestSerializer, CredentialDetailSerializer, CredentialSchemaVersionSerializer,
    CredentialSerializer, QuarantineCredentialSerializer, RevokeCredentialSerializer,
    RevocationRecordSerializer,
)
from .services import quarantine_credential, revoke_credential

logger = logging.getLogger(__name__)


class CredentialViewSet(GenericViewSet):
    """Read, revoke, and quarantine credentials."""

    pagination_class = StandardResultsPagination

    def get_queryset(self):
        return Credential.objects.select_related("schema_version").order_by("-created_at")

    def list(self, request):
        if not check_permission(request, "credential:read"):
            return error_response("Forbidden", status=403)

        qs = self.get_queryset()
        if inst := request.query_params.get("institution_id"):
            qs = qs.filter(institution_id=inst)
        if cycle := request.query_params.get("graduation_cycle_id"):
            qs = qs.filter(graduation_cycle_id=cycle)
        if st := request.query_params.get("status"):
            qs = qs.filter(status=st)

        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(CredentialSerializer(page, many=True).data)
        return Response(CredentialSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "credential:read"):
            return error_response("Forbidden", status=403)
        cred = get_object_or_404(self.get_queryset(), pk=pk)
        if check_permission(request, "credential:read_full"):
            return Response(CredentialDetailSerializer(cred).data)
        return Response(CredentialSerializer(cred).data)

    @action(detail=True, methods=["post"])
    def revoke(self, request, pk=None):
        if not check_permission(request, "credential:revoke"):
            return error_response("Forbidden", status=403)
        cred = get_object_or_404(self.get_queryset(), pk=pk)
        serializer = RevokeCredentialSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)
        try:
            record = revoke_credential(
                credential=cred,
                actor_id=getattr(request.user, "id", None),
                reason=serializer.validated_data["reason"],
            )
        except ValueError as exc:
            return error_response(str(exc), status=409)
        return success_response(RevocationRecordSerializer(record).data)

    @action(detail=True, methods=["post"])
    def quarantine(self, request, pk=None):
        if not check_permission(request, "credential:revoke"):
            return error_response("Forbidden", status=403)
        cred = get_object_or_404(self.get_queryset(), pk=pk)
        serializer = QuarantineCredentialSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response("Validation failed", status=400, detail=serializer.errors)
        try:
            quarantine_credential(
                credential=cred,
                actor_id=getattr(request.user, "id", None),
                reason=serializer.validated_data["reason"],
            )
        except ValueError as exc:
            return error_response(str(exc), status=409)
        return success_response(CredentialSerializer(cred).data)


class BatchIngestViewSet(GenericViewSet):
    """Submit and monitor batch credential ingest jobs."""

    parser_classes = [MultiPartParser]
    pagination_class = StandardResultsPagination

    def get_queryset(self):
        return BatchIngest.objects.order_by("-created_at")

    def list(self, request):
        if not check_permission(request, "credential:read"):
            return error_response("Forbidden", status=403)
        qs = self.get_queryset()
        if inst := request.query_params.get("institution_id"):
            qs = qs.filter(institution_id=inst)
        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(BatchIngestSerializer(page, many=True).data)
        return Response(BatchIngestSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "credential:read"):
            return error_response("Forbidden", status=403)
        batch = get_object_or_404(self.get_queryset(), pk=pk)
        return Response(BatchIngestSerializer(batch).data)

    @action(detail=True, methods=["get"])
    def report(self, request, pk=None):
        """GET /v1/registry/batches/{id}/report — per-row error report."""
        if not check_permission(request, "credential:read"):
            return error_response("Forbidden", status=403)
        batch = get_object_or_404(self.get_queryset(), pk=pk)
        return Response({
            "batch_id": str(batch.id),
            "transaction_id": str(batch.transaction_id),
            "status": batch.status,
            "total_records": batch.total_records,
            "success_count": batch.success_count,
            "failure_count": batch.failure_count,
            "row_errors": batch.row_errors,
            "completed_at": batch.completed_at.isoformat() if batch.completed_at else None,
        })

    def create(self, request):
        if not check_permission(request, "bulk:ingest"):
            return error_response("Forbidden", status=403)

        upload = request.FILES.get("file")
        if not upload:
            return error_response("No file provided.", status=400)

        file_bytes = upload.read()
        if len(file_bytes) > 100 * 1024 * 1024:
            return error_response("File exceeds 100 MB limit.", status=413)

        file_hash = hashlib.sha256(file_bytes).hexdigest()
        schema_id = request.data.get("schema_id")
        institution_id = request.data.get("institution_id")
        graduation_cycle_id = request.data.get("graduation_cycle_id")
        file_format = request.data.get("file_format", "json")

        if not schema_id:
            return error_response("schema_id is required.", status=400)

        # Institution ownership check (Task 19).
        # institution_officer can only submit for their own institution.
        if not check_permission(request, "institution:manage"):
            user_institution_id = str(getattr(request.user, "institution_id", "") or "")
            if not user_institution_id:
                return error_response(
                    "Your profile has no institution linked. Contact a registrar.", status=403
                )
            if user_institution_id != str(institution_id or ""):
                return error_response(
                    "You may only submit batches for your own institution.", status=403
                )

        try:
            schema = CredentialSchemaVersion.objects.filter(
                schema_id=schema_id, is_active=True
            ).order_by("-version").first()
            if not schema:
                return error_response(f"No active schema found for '{schema_id}'.", status=404)
        except Exception as exc:
            return error_response(str(exc), status=500)

        batch = BatchIngest.objects.create(
            institution_id=institution_id,
            graduation_cycle_id=graduation_cycle_id,
            schema_version=schema,
            submitted_by=getattr(request.user, "id", None),
            original_filename=upload.name,
            file_hash=file_hash,
            file_format=file_format,
        )

        from apps.registry.tasks import run_batch_ingest
        run_batch_ingest.apply_async(
            kwargs={"batch_id": str(batch.id), "file_bytes": file_bytes},
            queue="normal",
        )

        return success_response(BatchIngestSerializer(batch).data, status=202)


class SchemaVersionViewSet(GenericViewSet):
    """Read-only schema version catalog."""

    def list(self, request):
        if not check_permission(request, "credential:read"):
            return error_response("Forbidden", status=403)
        qs = CredentialSchemaVersion.objects.order_by("schema_id", "-version")
        return Response(CredentialSchemaVersionSerializer(qs, many=True).data)

    def retrieve(self, request, pk=None):
        if not check_permission(request, "credential:read"):
            return error_response("Forbidden", status=403)
        schema = get_object_or_404(CredentialSchemaVersion, pk=pk)
        return Response(CredentialSchemaVersionSerializer(schema).data)


class CredentialQueryView(APIView):
    """GET /v1/registry/credentials/query?graduate_index_number=<idx>

    Minimised lookup endpoint for NLEMS/NBES inter-system queries.
    Returns only credential_ref, status, degree_classification, programme_code.
    Requires credential:read permission.
    """

    def get(self, request):
        if not check_permission(request, "credential:read"):
            return error_response("Forbidden", status=403)

        gin = request.query_params.get("graduate_index_number", "").strip()
        waec = request.query_params.get("waec_index", "").strip()

        if not gin and not waec:
            return error_response(
                "At least one of 'graduate_index_number' or 'waec_index' is required.", status=400
            )

        qs = Credential.objects.all()
        if gin:
            qs = qs.filter(graduate_index_number=gin)
        if waec:
            qs = qs.filter(waec_index=waec)

        results = [
            {
                "credential_ref": c.credential_ref,
                "status": c.status,
                "degree_classification": c.degree_classification,
                "programme_code": c.programme_code,
                "institution_code": c.institution_code,
                "graduate_index_number": c.graduate_index_number,
            }
            for c in qs[:20]
        ]
        return Response({"results": results, "count": len(results)})
