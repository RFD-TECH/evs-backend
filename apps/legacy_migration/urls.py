"""URL configuration for legacy migration (EVS-F09)."""
from django.urls import path

from .views import (
    AffidavitVerifyView,
    AuditReportGenerateView,
    AuditReportSignAdminView,
    AuditReportSignRegistrarView,
    AuditReportView,
    ConfirmRecordView,
    CredentialVersionListView,
    LegacyBatchDetailView,
    LegacyBatchIngestView,
    LegacyBatchListView,
    MigrationWaveDetailView,
    MigrationWaveListCreateView,
    RecordCorrectionView,
    WaveActivateView,
    WaveGoLiveView,
    WaveQuarantineView,
    WaveRollbackView,
)

app_name = "legacy_migration"

urlpatterns = [
    # Migration waves
    path("waves/", MigrationWaveListCreateView.as_view(), name="wave-list"),
    path("waves/<uuid:pk>/", MigrationWaveDetailView.as_view(), name="wave-detail"),
    path("waves/<uuid:pk>/activate/", WaveActivateView.as_view(), name="wave-activate"),
    path("waves/<uuid:pk>/go-live/", WaveGoLiveView.as_view(), name="wave-go-live"),
    path("waves/<uuid:pk>/rollback/", WaveRollbackView.as_view(), name="wave-rollback"),
    path("waves/<uuid:pk>/quarantine/", WaveQuarantineView.as_view(), name="wave-quarantine"),
    # Audit report
    path("waves/<uuid:pk>/audit-report/", AuditReportView.as_view(), name="audit-report"),
    path("waves/<uuid:pk>/audit-report/generate/", AuditReportGenerateView.as_view(), name="audit-report-generate"),
    path("waves/<uuid:pk>/audit-report/sign-admin/", AuditReportSignAdminView.as_view(), name="audit-report-sign-admin"),
    path("waves/<uuid:pk>/audit-report/sign-registrar/", AuditReportSignRegistrarView.as_view(), name="audit-report-sign-registrar"),
    # Batches
    path("batches/", LegacyBatchListView.as_view(), name="batch-list"),
    path("batches/ingest/", LegacyBatchIngestView.as_view(), name="batch-ingest"),
    path("batches/<uuid:pk>/", LegacyBatchDetailView.as_view(), name="batch-detail"),
    path("batches/<uuid:pk>/verify-affidavit/", AffidavitVerifyView.as_view(), name="batch-verify-affidavit"),
    path("batches/<uuid:pk>/confirm/", ConfirmRecordView.as_view(), name="batch-confirm"),
    # Record corrections and versions
    path("records/<uuid:credential_id>/correct/", RecordCorrectionView.as_view(), name="record-correct"),
    path("records/<uuid:credential_id>/versions/", CredentialVersionListView.as_view(), name="record-versions"),
]
