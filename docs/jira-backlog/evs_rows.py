# EVS — Examination Verification System (System 03) Jira backlog rows.
# Derived from /home/user/evs-backend code inventory. Mirrors the IAM System19 reference format.

def E(summary, link, priority, sprint, labels, status, desc):
    return dict(issue_type="Epic", summary=summary, epic_name=summary, epic_link=link,
                priority=priority, story_points=None, sprint=sprint, labels=labels,
                status=status, description=desc)

def S(summary, link, name, priority, sp, sprint, labels, status, desc):
    return dict(issue_type="Story", summary=summary, epic_name=name, epic_link=link,
                priority=priority, story_points=sp, sprint=sprint, labels=labels,
                status=status, description=desc)

ROWS = []

# ============ EVS-F01 Credential Registry, Batch Ingest & Revocation ============
n = "EVS-F01 — Credential Registry, Batch Ingest & Revocation"
ROWS += [
 E(n, "EVS-F01", "Highest", "Sprint 1", "EVS-F01 phase-1 srs-must registry ingest", "Partial",
   "SRS-EVS-F01: Institutions submit graduation credentials as batches (≤10k records / 100 MB); each Credential is canonicalised, SHA-256 anchored, immutable once written, and revocable via an append-only RevocationRecord."),
 S("F01-1 Credential model: canonical JSONB payload, sha256_hash anchor, status lifecycle", "EVS-F01", n,
   "Highest", 5, "Sprint 1", "EVS-F01 phase-1 srs-must F01-1 credential", "Done",
   "SRS-EVS-F01 / F01-1: registry/models.py Credential carries canonical payload, unique sha256_hash, qr_payload, and status (active|revoked|quarantined|suspended); only status transitions are permitted after write."),
 S("F01-2 Atomic batch ingest with two-phase validate-then-write and row-level errors", "EVS-F01", n,
   "Highest", 5, "Sprint 1", "EVS-F01 phase-1 srs-must F01-2 batch", "Done",
   "SRS-EVS-F01 / F01-2: run_batch_ingest() task + process_batch_ingest() (registry/services.py) validate all records, write valid ones atomically via _register_one_atomic(), and record {row,ref,error} on BatchIngest.row_errors; GET /v1/batch-ingest/{id}/errors surfaces them."),
 S("F01-3 Canonical JSON + SHA-256 tamper anchor (sorted keys, NFC normalisation)", "EVS-F01", n,
   "High", 3, "Sprint 1", "EVS-F01 phase-1 srs-must F01-3 canonical", "Done",
   "SRS-EVS-F01 / F01-3: registry/canonicaliser.py canonical_json() and sha256_of_canonical() produce the deterministic hash that every verification channel re-checks; confirm NFC string normalisation is applied to all PII fields."),
 S("F01-4 Credential revocation + quarantine with append-only RevocationRecord", "EVS-F01", n,
   "High", 3, "Sprint 1", "EVS-F01 phase-1 srs-must F01-4 revoke", "Done",
   "SRS-EVS-F01 / F01-4: revoke_credential() and quarantine_credential() (registry/services.py) atomically flip status, write a RevocationRecord (source confirmed_fraud|admin|dg), emit an audit event, and publish to the outbox; POST /v1/credentials/{id}/revoke|quarantine."),
 S("F01-5 Idempotent batch submission keyed on transaction_id", "EVS-F01", n,
   "Medium", 2, "Sprint 1", "EVS-F01 phase-1 srs-must F01-5 idempotency", "Done",
   "SRS-EVS-F01 / F01-5: BatchIngest.transaction_id is the idempotency key; verify a re-submitted transaction_id returns the existing run rather than reprocessing the file."),
 S("F01-6 Streaming/chunked upload for cohorts beyond the 10k / 100 MB hard limit", "EVS-F01", n,
   "Medium", 5, "Sprint 7", "EVS-F01 phase-3 srs-should F01-6 streaming", "To Do",
   "SRS-EVS-F01 / F01-6: batch ingest enforces a hard 10,000-record / 100 MB limit with no chunked path; add streaming upload + multi-part assembly so large institutional cohorts can be ingested in one logical batch."),
]

# ============ EVS-F02 Credential Schema Versioning & Integrity Sweep ============
n = "EVS-F02 — Credential Schema Versioning & Nightly Integrity Sweep"
ROWS += [
 E(n, "EVS-F02", "High", "Sprint 2", "EVS-F02 phase-1 srs-must schema integrity", "Done",
   "SRS-EVS-F02: Credential payloads validate against versioned draft-07 JSON Schemas; a nightly sweep re-hashes the full corpus, builds a merkle root, and quarantines tampered credentials."),
 S("F02-1 CredentialSchemaVersion: versioned draft-07 schemas with required-field enforcement", "EVS-F02", n,
   "High", 3, "Sprint 2", "EVS-F02 phase-1 srs-must F02-1 schema", "Done",
   "SRS-EVS-F02 / F02-1: registry CredentialSchemaVersion stores schema_json/required_fields/is_active; _validate_record() checks required fields per SRS §4.2; GET/POST /v1/schemas manages versions and deprecation."),
 S("F02-2 nightly_integrity_sweep: full-corpus SHA-256 re-check with merkle root", "EVS-F02", n,
   "High", 5, "Sprint 2", "EVS-F02 phase-1 srs-must F02-2 sweep", "Done",
   "SRS-EVS-F02 / F02-2: nightly_integrity_sweep() task records an IntegrityRun (total_checked, tampered_count, merkle_root); GET /v1/integrity/runs exposes history; tampered credentials raise a SecurityEvent and are quarantined."),
 S("F02-3 Publish IntegrityRun digest to System 22 as a standalone anchor", "EVS-F02", n,
   "Medium", 3, "Sprint 6", "EVS-F02 phase-2 srs-should F02-3 anchor", "Partial",
   "SRS-EVS-F02 / F02-3: the sweep merkle_root is currently only embedded in the DailyCommitment; publish the IntegrityRun digest separately to System 22 so the corpus integrity proof is independently verifiable."),
]

# ============ EVS-F03 QR Scan Verification ============
n = "EVS-F03 — Real-time QR Scan Verification"
ROWS += [
 E(n, "EVS-F03", "Highest", "Sprint 2", "EVS-F03 phase-1 srs-must verify qr", "Done",
   "SRS-EVS-F03/F05: Public GET /v1/verify/{credential_id}?token= validates the signed QR JWT, re-checks the tamper seal before status, applies a cached revocation check, and returns a structured result within a ≤2 s SLA."),
 S("F05-1 PublicVerifyView QR flow: JWT signature, sub-claim binding, tamper-then-status order", "EVS-F03", n,
   "Highest", 5, "Sprint 2", "EVS-F03 phase-1 srs-must F05-1 qr-verify", "Done",
   "SRS-EVS-F03 / F05-1: verification/service.py verify_credential() decodes/validates the QR JWT (5-min skew), binds the sub claim to the URL id, checks the SHA-256 tamper seal BEFORE status, and returns {result,message,data,verification_ms,checks_passed}."),
 S("F05-2 Constant-time tamper comparison + SecurityEvent on tamper detection", "EVS-F03", n,
   "High", 3, "Sprint 2", "EVS-F03 phase-1 srs-must F05-2 tamper", "Done",
   "SRS-EVS-F03 / F05-2: _hashes_equal() does a constant-time compare and _raise_tamper_event() writes a SecurityEvent when the recomputed hash diverges; every attempt is logged as a VerificationSession via the outbox."),
 S("F05-3 60-second revocation cache for sub-2s public verification", "EVS-F03", n,
   "Medium", 2, "Sprint 2", "EVS-F03 phase-1 srs-must F05-3 revocation-cache", "Partial",
   "SRS-EVS-F03 / F05-3: _is_revoked_cached() hits RevocationRecord with a 60-second in-process cache; the TTL is hardcoded — make it configurable and confirm cache coherence across web workers."),
 S("F05-4 VerificationSession evidence capture with 10-year retention", "EVS-F03", n,
   "Medium", 2, "Sprint 2", "EVS-F03 phase-1 srs-must F05-4 session", "Done",
   "SRS-EVS-F03 / F05-4: VerificationSession records channel, result, verifier_ip/user_agent, device_fingerprint, jwt_kid and verification_ms; device_fingerprint is captured but not yet used in verification logic."),
]

# ============ EVS-F06 PDF PAdES Verification ============
n = "EVS-F06 — PDF PAdES Signature Verification & Trust Anchors"
ROWS += [
 E(n, "EVS-F06", "High", "Sprint 3", "EVS-F06 phase-1 srs-must verify pdf pades", "Partial",
   "SRS-EVS-F06: POST /v1/verify/pdf extracts each PDF signature, validates byte-range integrity, chain-to-trust-anchor, OCSP/CRL revocation and PAdES profile (B-T/B-LT/B-LTA), and stores artefacts in the content-addressable DocumentVault."),
 S("F06-1 verify_pdf: per-signature integrity, chain, revocation and profile checks", "EVS-F06", n,
   "High", 5, "Sprint 3", "EVS-F06 phase-1 srs-must F06-1 pades", "Partial",
   "SRS-EVS-F06 / F06-1: pdf_service.py verify_pdf()/_validate_signature() records a PdfSignatureOutcome per signature (integrity_ok, chain_ok, revocation_status, profile, timestamp_ok) using pyhanko/pypdf; finish OCSP/CRL handling so 'unchecked' revocation is retried not silently passed."),
 S("F06-2 TrustAnchor CA registry drives PDF chain validation", "EVS-F06", n,
   "High", 3, "Sprint 3", "EVS-F06 phase-1 srs-must F06-2 trust-anchor", "Done",
   "SRS-EVS-F06 / F06-2: TrustAnchor model (ca_certificate_pem, ocsp_endpoint, crl_endpoint, status) is managed via /v1/verify/trust-anchors and is the trust root for chain_ok; only trust_anchor:manage may mutate it."),
 S("F06-3 Configurable TSA endpoint for B-LT/B-LTA timestamp validation", "EVS-F06", n,
   "Medium", 3, "Sprint 3", "EVS-F06 phase-2 srs-must F06-3 tsa", "To Do",
   "SRS-EVS-F06 / F06-3: timestamp_ok is computed for B-LT/B-LTA profiles but the Time-Stamp Authority endpoint is implicit/environment-derived; add explicit TSA configuration and assert timestamp tokens validate against it."),
 S("F06-4 Multi-signature PDFs: report per-signature outcomes instead of all-or-nothing", "EVS-F06", n,
   "Medium", 3, "Sprint 3", "EVS-F06 phase-2 srs-should F06-4 multisig", "Partial",
   "SRS-EVS-F06 / F06-4: a single failed signature collapses the result to invalid_signature; surface the per-signature PdfSignatureOutcome set so verifiers see which signature failed and why."),
 S("F06-5 DocumentVault: content-addressable, HSM-encrypted artefact store with 10-year retention", "EVS-F06", n,
   "Medium", 3, "Sprint 3", "EVS-F06 phase-1 srs-must F06-5 vault", "Done",
   "SRS-EVS-F06 / F06-5: DocumentVaultObject stores artefacts by SHA-256 with encryption_kid, retention_until (10y), tamper_flag and virus_clean; _ensure_vault_object()/_mark_vault_tampered() wire it into PDF and uploaded-QR flows."),
]

# ============ EVS-F07 Uploaded-QR Verification ============
n = "EVS-F07 — Uploaded-QR Verification from Image/PDF"
ROWS += [
 E(n, "EVS-F07", "Medium", "Sprint 3", "EVS-F07 phase-1 srs-must verify uploaded-qr", "Done",
   "SRS-EVS-F07: POST /v1/verify/uploaded-qr decodes a QR code from an uploaded PNG/JPEG/PDF, extracts the JWT, runs the same verify_credential pipeline, and vaults the uploaded file."),
 S("F07-1 verify_uploaded_qr: decode QR from image/PDF and reuse the QR verify pipeline", "EVS-F07", n,
   "Medium", 5, "Sprint 3", "EVS-F07 phase-1 srs-must F07-1 decode", "Done",
   "SRS-EVS-F07 / F07-1: qr_upload_service.py verify_uploaded_qr() uses pyzbar+PIL (_decode_qr) to extract the QR/JWT then calls verify_credential(); the source file is stored via _ensure_vault_object()."),
]

# ============ EVS-F04 WAEC Connector & Resilience ============
n = "EVS-F04 — WAEC Connector, Circuit Breaker & Manual Queue"
ROWS += [
 E(n, "EVS-F04", "High", "Sprint 4", "EVS-F04 phase-1 srs-must waec connector resilience", "Partial",
   "SRS-EVS-F04: External WAEC grade verification with a per-connector circuit breaker, synthetic health probes, exponential backoff (≤5 s p95), PII-masked responses, and a manual fallback queue when the breaker is open."),
 S("F04-1 verify_waec: retry/backoff, response sanitisation, manual-queue fallback", "EVS-F04", n,
   "High", 5, "Sprint 4", "EVS-F04 phase-1 srs-must F04-1 waec", "Partial",
   "SRS-EVS-F04 / F04-1: connectors/waec_service.py verify_waec() wraps _call_waec() with ≤3 retries/backoff, _sanitise_response() PII masking and _mask_dob(), and _enqueue_manual() when the breaker is open; blocked on OAuth token retrieval below."),
 S("F04-2 Implement _get_access_token: HSM-decrypted OAuth credential for WAEC", "EVS-F04", n,
   "High", 5, "Sprint 4", "EVS-F04 phase-1 srs-must F04-2 oauth", "To Do",
   "SRS-EVS-F04 / F04-2: connectors/waec_service.py:247 _get_access_token() returns an empty string — WAEC calls are effectively unauthenticated. Implement OAuth token fetch by decrypting the ConnectorCredential value via the HSM key (value_kid)."),
 S("F04-3 Circuit breaker + synthetic health probes with state transitions", "EVS-F04", n,
   "High", 3, "Sprint 4", "EVS-F04 phase-1 srs-must F04-3 breaker", "Partial",
   "SRS-EVS-F04 / F04-3: monitor_connector_health() probes every 5 min and run_circuit_breaker() opens at >15% errors over a 100-request window (BreakerState/ConnectorHealth); define the half-open probe payload so the breaker can auto-close."),
 S("F04-4 Manual verification queue with SLA escalation to Secretariat", "EVS-F04", n,
   "Medium", 3, "Sprint 4", "EVS-F04 phase-1 srs-must F04-4 manual-queue", "Done",
   "SRS-EVS-F04 / F04-4: ManualQueueItem (pending|claimed|resolved|escalated) plus claim/resolve endpoints and escalate_stale_queue_items() auto-escalate past sla_due_at."),
 S("F04-5 WAEC request history with sanitised response audit trail (F08)", "EVS-F04", n,
   "Medium", 2, "Sprint 4", "EVS-F04 phase-1 srs-must F08 waec-history", "Done",
   "SRS-EVS-F08: WaecRequest captures index_number, masked DOB, request_payload_hash, response_status and sanitised_response; GET /v1/waec-requests exposes the queryable history."),
 S("F04-6 Promote connector sandbox→production with 24h sandbox validation gate", "EVS-F04", n,
   "Medium", 3, "Sprint 4", "EVS-F04 phase-2 srs-should F04-6 lifecycle", "Done",
   "SRS-EVS-F04: Connector lifecycle_state transitions via POST /v1/connectors/{id}/promote and /suspend; ConnectorCredential stores HSM-encrypted secrets (never plaintext) with rotation metadata."),
]

# ============ EVS-F05 Fraud Detection & Watchlist ============
n = "EVS-F05 — Fraud Detection, Rules Engine & Watchlist"
ROWS += [
 E(n, "EVS-F05", "High", "Sprint 5", "EVS-F05 phase-1 srs-must fraud detection watchlist", "Partial",
   "SRS-EVS-F05: Configurable, dual-control fraud rules run post-ingest and nightly over the credential corpus, raising immutable FraudFlag evidence packages, maintaining a cross-system watchlist, and recording every FlagAction."),
 S("F05-1 nightly_fraud_sweep + post_ingest_detection over the credential corpus", "EVS-F05", n,
   "High", 5, "Sprint 5", "EVS-F05 phase-1 srs-must F05-1 sweep", "Done",
   "SRS-EVS-F05 / F05-1: nightly_fraud_sweep() and post_ingest_detection() (fraud_detection/tasks.py) evaluate all enabled rules and record a RuleRun (records_scanned, rules_evaluated, flags_created)."),
 S("F05-2 Dual-control RuleDefinition: versioned, two-approver activation", "EVS-F05", n,
   "High", 3, "Sprint 5", "EVS-F05 phase-1 srs-must F05-2 dual-control", "Done",
   "SRS-EVS-F05 / F05-2: RuleDefinition requires created_by, approved_by and a distinct second_approver before effective_from; POST /v1/rules/{id}/activate enforces the dual-control approval."),
 S("F05-3 Define the predicate DSL JSON Schema and parameterise fuzzy thresholds", "EVS-F05", n,
   "High", 5, "Sprint 5", "EVS-F05 phase-1 srs-must F05-3 dsl", "To Do",
   "SRS-EVS-F05 / F05-3: rules_engine.py evaluate_predicate() tree-walks predicate_json but no schema defines its structure and detect_duplicates() uses a hardcoded Levenshtein threshold; publish a predicate DSL JSON Schema and make the fuzzy similarity threshold configurable."),
 S("F05-4 FraudFlag resolution with mandatory ≥30-word justification", "EVS-F05", n,
   "Medium", 3, "Sprint 5", "EVS-F05 phase-1 srs-must F05-4 resolve", "Done",
   "SRS-EVS-F05 / F05-4: FraudFlag (status new|under_investigation|confirmed_fraud|false_positive) requires a ≥30-word resolution_justification; POST /v1/fraud-flags/{id}/resolve records resolver_id, resolved_at and audit_hash."),
 S("F05-5 Sign and store FraudFlag evidence bundles in MinIO", "EVS-F05", n,
   "Medium", 3, "Sprint 5", "EVS-F05 phase-2 srs-should F05-5 evidence", "To Do",
   "SRS-EVS-F05 / F05-5: FraudFlag.evidence_bundle_uri is returned but the ZIP is never built, signed or uploaded; implement evidence-bundle generation with HSM signature and MinIO storage."),
 S("F05-6 Watchlist with 60s freshness push to NLEMS/NBES/FCA", "EVS-F05", n,
   "Medium", 3, "Sprint 5", "EVS-F05 phase-2 srs-must F05-6 watchlist", "Partial",
   "SRS-EVS-F05 / F05-6: WatchlistEntry (active|cleared) is queryable at /v1/watchlist; wire the 60-second freshness push so confirmed fraud propagates to NLEMS/NBES/FCA via the outbox."),
 S("F05-7 Auto-escalate stale fraud flags older than 7 days", "EVS-F05", n,
   "Low", 2, "Sprint 5", "EVS-F05 phase-2 srs-should F05-7 escalate", "Done",
   "SRS-EVS-F05 / F05-7: auto_escalate_stale_flags() escalates flags unresolved >7 days to the Secretariat via _notify_escalation() to System 21."),
]

# ============ EVS-F03-FCA Foreign Credential Assessment ============
n = "EVS-FCA — Foreign Credential Assessment Workflow"
ROWS += [
 E(n, "EVS-FCA", "High", "Sprint 6", "EVS-FCA phase-2 srs-must foreign-credentials workflow", "Partial",
   "SRS-EVS-F03(FCA): An 11/12-stage Foreign Credential Assessment from submission through triage, assessor recommendation, registrar review and HSM-backed DG sign-off, with a 28-day SLA and an immutable transition trail."),
 S("FCA-1 ForeignCredentialApplication 12-stage workflow with WorkflowTransition trail", "EVS-FCA", n,
   "High", 5, "Sprint 6", "EVS-FCA phase-2 srs-must FCA-1 workflow", "Done",
   "SRS-EVS-FCA / FCA-1: foreign_credentials models drive the submitted→…→dg_signed→closed state machine; every change writes an immutable WorkflowTransition; reference generated as FCA-YYYY-NNNN."),
 S("FCA-2 Triage routing (internal vs GTEC) sets the 28-day SLA clock", "EVS-FCA", n,
   "High", 3, "Sprint 6", "EVS-FCA phase-2 srs-must FCA-2 triage", "Partial",
   "SRS-EVS-FCA / FCA-2: POST /v1/foreign-credentials/{id}/triage routes internal|gtec and sets sla_due_at = triaged_at + 28 days; the GTEC path has no dedicated routing/service yet — only a generic Connector reference."),
 S("FCA-3 Assessor recommendation + registrar review transitions", "EVS-FCA", n,
   "High", 3, "Sprint 6", "EVS-FCA phase-2 srs-must FCA-3 assess", "Done",
   "SRS-EVS-FCA / FCA-3: assign-assessor, recommend and registrar-review endpoints move the application through AssessorAssignment and recommendation states; GET /history and /recommendations expose the trail."),
 S("FCA-4 DG sign-off: HSM-backed decision with committed decision_sha256 (step-up MFA)", "EVS-FCA", n,
   "High", 5, "Sprint 6", "EVS-FCA phase-2 srs-must FCA-4 dg-sign", "Partial",
   "SRS-EVS-FCA / FCA-4: POST /v1/foreign-credentials/{id}/dg-sign requires step-up MFA and commits decision_sha256, but there is no explicit DGDecision model/witness payload and signing depends on the HSM PKCS#11 work (EVS-HSM)."),
 S("FCA-5 FCA SLA escalation and System 21 status dispatch", "EVS-FCA", n,
   "Medium", 2, "Sprint 6", "EVS-FCA phase-2 srs-should FCA-5 sla", "Done",
   "SRS-EVS-FCA / FCA-5: send_fca_status_update() pushes stage changes to System 21 and escalate_sla_fca() escalates applications past sla_due_at; background_document_scan() virus-scans uploads."),
]

# ============ EVS-F09 Legacy Migration ============
n = "EVS-F09 — Legacy Credential Migration"
ROWS += [
 E(n, "EVS-F09", "High", "Sprint 6", "EVS-F09 phase-2 srs-must legacy migration", "Partial",
   "SRS-EVS-F09: Legacy records migrate in named waves (planned→active→live, rollback never deletes); institutions confirm per-record within a 14-day window, and a dual-signed pre-go-live audit is anchored to System 22."),
 S("F09-1 MigrationWave + LegacyBatch lifecycle with notarised affidavit gate", "EVS-F09", n,
   "High", 5, "Sprint 6", "EVS-F09 phase-2 srs-must F09-1 wave", "Done",
   "SRS-EVS-F09 / F09-1: MigrationWave (planned→active→live|rolled_back|quarantined) and LegacyBatch require affidavit_verified by the Registrar before go-live; activate/go-live/rollback endpoints drive the state machine."),
 S("F09-2 ingest_legacy_batch: migrated credentials get the same UUID/SHA256/QR as new awards", "EVS-F09", n,
   "High", 3, "Sprint 6", "EVS-F09 phase-2 srs-must F09-2 ingest", "Done",
   "SRS-EVS-F09 / F09-2: ingest_legacy_batch() parses CSV/JSON and creates Credentials with legacy=True/wave_id, sharing the canonical SHA-256 + signed QR pipeline so verification is identical to new awards."),
 S("F09-3 14-day per-record institution confirmation window", "EVS-F09", n,
   "Medium", 3, "Sprint 6", "EVS-F09 phase-2 srs-must F09-3 confirm", "Done",
   "SRS-EVS-F09 / F09-3: LegacyConfirmation captures per-record confirmed|rejected decisions; monitor_confirmation_deadline() flags unconfirmed records past the 14-day window for manual review."),
 S("F09-4 Define rollback re-activation semantics and quarantine reason taxonomy", "EVS-F09", n,
   "Medium", 3, "Sprint 7", "EVS-F09 phase-3 srs-should F09-4 rollback", "To Do",
   "SRS-EVS-F09 / F09-4: the rolled_back/quarantined transitions exist but credential re-activation logic is unclear and quarantine_reason is free-text; specify rollback re-activation and a quarantine reason taxonomy."),
 S("F09-5 Dual-signed pre-go-live audit report anchored to System 22", "EVS-F09", n,
   "Medium", 3, "Sprint 7", "EVS-F09 phase-3 srs-must F09-5 audit", "Partial",
   "SRS-EVS-F09 / F09-5: publish_wave_pre_golive_audit() produces a dual-signed (Admin + Registrar) report anchored to System 22; formalise the dual-signature mechanics and witness capture."),
]

# ============ EVS-F00 Institutions & Graduation Cycle SLA ============
n = "EVS-F00 — Institutions & Graduation Cycle SLA"
ROWS += [
 E(n, "EVS-F00", "Medium", "Sprint 7", "EVS-F00 phase-2 srs-must institutions cycles sla", "Partial",
   "SRS-EVS-F00: Accredited institutions own graduation cycles with statutory submission deadlines; D-20 and D-28 reminders and overdue escalations are tracked as SlaEvents."),
 S("F00-1 InstitutionMaster + GraduationCycle submission-window model", "EVS-F00", n,
   "Medium", 3, "Sprint 7", "EVS-F00 phase-2 srs-must F00-1 institution", "Done",
   "SRS-EVS-F00 / F00-1: InstitutionMaster (code, accreditation_number, contact_officers) and GraduationCycle (year, session, submission_deadline, status) are managed via /v1/institutions and /v1/cycles with a submit lock."),
 S("F00-2 D-20 / D-28 SLA reminders and overdue escalation", "EVS-F00", n,
   "Medium", 2, "Sprint 7", "EVS-F00 phase-2 srs-must F00-2 sla", "Done",
   "SRS-EVS-F00 / F00-2: send_d20_reminder(), send_d28_reminder() and mark_overdue() emit SlaEvent rows and set the sla_d20_notified/sla_d28_notified flags on each cycle."),
 S("F00-3 Institution API-key issuance, rotation and revocation", "EVS-F00", n,
   "Medium", 3, "Sprint 7", "EVS-F00 phase-3 srs-should F00-3 api-keys", "To Do",
   "SRS-EVS-F00 / F00-3: InstitutionMaster stores hashed api_keys metadata but there is no issuance/rotation/revocation flow; add managed institution API-key lifecycle with hashed-at-rest storage."),
]

# ============ EVS-N19 RBAC ============
n = "EVS-N19 — RBAC, Permission Matrix & Separation of Duties"
ROWS += [
 E(n, "EVS-N19", "High", "Sprint 1", "EVS-N19 phase-1 srs-must rbac iam", "Partial",
   "SRS-EVS-N19: IAM (System 19) owns role assignment via Keycloak evs-api client roles; EVS mirrors roles into UserRole on every request, enforces a runtime-editable permission matrix, and enforces Separation of Duties."),
 S("N19-1 Keycloak JWT auth with auto-provisioned UserProfile and JWT role sync", "EVS-N19", n,
   "High", 3, "Sprint 1", "EVS-N19 phase-1 srs-must N19-1 auth", "Done",
   "SRS-EVS-N19 / N19-1: shared/auth.py KeycloakJWTAuthentication auto-creates UserProfile on first login and sync_user_roles_from_jwt() reconciles resource_access roles into UserRole, emitting RoleChangeEvent rows."),
 S("N19-2 Runtime-configurable RolePermission matrix", "EVS-N19", n,
   "High", 3, "Sprint 1", "EVS-N19 phase-1 srs-must N19-2 matrix", "Done",
   "SRS-EVS-N19 / N19-2 (REQ-EVS-F00-02): Role/Permission/RolePermission tables make the grant matrix runtime-editable via PUT /v1/roles/{id}/permissions; shared/permissions.py enforces check_permission() with a 60s RBAC cache."),
 S("N19-3 Separation-of-Duties via RoleMutualExclusion", "EVS-N19", n,
   "Medium", 2, "Sprint 1", "EVS-N19 phase-1 srs-must N19-3 sod", "Done",
   "SRS-EVS-N19 / N19-3: RoleMutualExclusion declares mutually-exclusive role pairs surfaced at /v1/mutual-exclusions; verify both elevated and non-elevated assignment paths reject conflicting pairs."),
 S("N19-4 Step-up MFA enforcement on signing/sign-off actions", "EVS-N19", n,
   "Medium", 3, "Sprint 2", "EVS-N19 phase-1 srs-must N19-4 step-up", "Partial",
   "SRS-EVS-N19 / N19-4: DG sign, AG export and go-live sign-off require step-up MFA via the X-MFA-Verified header; formalise the contract with System 19 so the header is cryptographically asserted, not merely trusted."),
]

# ============ EVS-N01 Immutable Audit Hash Chain & Anchoring ============
n = "EVS-N01 — Immutable Audit Hash Chain & Daily Anchoring"
ROWS += [
 E(n, "EVS-N01", "High", "Sprint 3", "EVS-N01 phase-1 srs-must audit hash-chain anchoring", "Done",
   "SRS-EVS-N01: An append-only, SHA-256 hash-chained AuditEvent log is relayed to System 17 via a transactional outbox, anchored daily to System 22 (DailyHashAnchor + cryptographic DailyCommitment)."),
 S("N01-1 AuditEvent SHA-256 chain with append-only DB enforcement", "EVS-N01", n,
   "High", 3, "Sprint 3", "EVS-N01 phase-1 srs-must N01-1 chain", "Done",
   "SRS-EVS-N01 / N01-1: audit/models.py AuditEvent computes a chain_hash linking each event to its predecessor; UPDATE/DELETE are blocked so the log is append-only with 10-year retention."),
 S("N01-2 Transactional outbox relay to System 17 / Kafka", "EVS-N01", n,
   "High", 3, "Sprint 3", "EVS-N01 phase-1 srs-must N01-2 outbox", "Done",
   "SRS-EVS-N01 / N01-2: OutboxEvent + poll_outbox() (every 5s) relay event batches to Kafka via System 17; shared/events.py publish() is the single write path used across all apps."),
 S("N01-3 daily_hash_anchor: publish previous-day chain root to System 22", "EVS-N01", n,
   "High", 3, "Sprint 3", "EVS-N01 phase-1 srs-must N01-3 anchor", "Done",
   "SRS-EVS-N01 / N01-3: daily_hash_anchor() (02:00 UTC) writes a DailyHashAnchor (head_event_id, head_hash, event_count) and exports it to System 22."),
 S("N01-4 build_daily_commitment: HSM-signed commitment chaining merkle root + head hash", "EVS-N01", n,
   "High", 5, "Sprint 3", "EVS-N01 phase-1 srs-must N01-4 commitment", "Done",
   "SRS-EVS-N01 / N01-4: build_daily_commitment() (02:30 UTC) chains integrity_merkle_root + prev_commitment_hash into a DailyCommitment, signs it via _sign_commitment() (HSM or HMAC fallback), and _submit_commitment_to_s22() posts it with 3× backoff."),
 S("N01-5 SecurityEvent log with 90-day retention tuning", "EVS-N01", n,
   "Medium", 2, "Sprint 3", "EVS-N01 phase-1 srs-should N01-5 security-events", "Done",
   "SRS-EVS-N01 / N01-5: SecurityEvent captures auth failures, token issues, fraud flags and throttling; cleanup_security_events() prunes rows older than 90 days."),
]

# ============ EVS-N06 AG Export & Tiered Retention ============
n = "EVS-N06 — Auditor-General Signed Export & Tiered Retention"
ROWS += [
 E(n, "EVS-N06", "High", "Sprint 5", "EVS-N06 phase-3 srs-must ag-export retention", "Done",
   "SRS-EVS-N06: The Auditor-General can request signed, tamper-evident audit export bundles (step-up MFA, rate-limited); audit data tiers hot→warm→cold (90d/3y/10y) into MinIO."),
 S("N06-1 ExportRequest: HSM-signed AG bundle with step-up MFA and 5/day rate limit", "EVS-N06", n,
   "High", 5, "Sprint 5", "EVS-N06 phase-3 srs-must N06-1 export", "Done",
   "SRS-EVS-N06 / N06-1: POST /v1/audit/exports creates an ExportRequest; run_auditor_general_export() builds via build_export_bundle(), HSM-signs the bundle and records bundle_hash; capped at 5/day."),
 S("N06-2 Tiered retention migration hot→warm→cold to MinIO", "EVS-N06", n,
   "Medium", 3, "Sprint 5", "EVS-N06 phase-3 srs-must N06-2 retention", "Done",
   "SRS-EVS-N06 / N06-2: run_tiered_retention_migration() migrates AuditEvents across hot (90d) / warm (3y) / cold (10y) tiers into MinIO, recording a RetentionTierLog with manifest_hash and HSM signature."),
]

# ============ EVS-HSM Signing (PKCS#11) ============
n = "EVS-HSM — HSM Signing Service (PKCS#11)"
ROWS += [
 E(n, "EVS-HSM", "Highest", "Sprint 8", "EVS-HSM phase-3 srs-must hsm pkcs11 blocker", "Partial",
   "SRS-EVS-HSM: All QR JWTs, credential signatures, DG decisions and daily commitments must be HSM-signed via PKCS#11 in production (SoftHSM2/appliance). Only the dev HS256 software path works today — PKCS#11 is unimplemented and is a go-live blocker."),
 S("HSM-1 Implement PKCS#11 sign_with_key for credential/DG/commitment signing", "EVS-HSM", n,
   "Highest", 8, "Sprint 8", "EVS-HSM phase-3 srs-must HSM-1 sign", "To Do",
   "SRS-EVS-HSM / HSM-1: apps/hsm/service.py:95 sign_with_key() and :102 _sign_pkcs11() raise NotImplementedError; implement PKCS#11 signing against SoftHSM2/HSM for the qr_jwt_sign, dg_sign and credential_sign key purposes."),
 S("HSM-2 Implement PKCS#11 verify_qr_token for production QR verification", "EVS-HSM", n,
   "Highest", 5, "Sprint 8", "EVS-HSM phase-3 srs-must HSM-2 verify", "To Do",
   "SRS-EVS-HSM / HSM-2: apps/hsm/service.py:52 verify_qr_token() raises NotImplementedError for PKCS#11; implement production QR JWT verification with the 5-minute clock-skew leeway and active-key (kid) selection."),
 S("HSM-3 JWKS exposes active HSM public keys for external verifiers", "EVS-HSM", n,
   "High", 3, "Sprint 8", "EVS-HSM phase-1 srs-must HSM-3 jwks", "Done",
   "SRS-EVS-HSM / HSM-3: GET /v1/hsm/jwks (AllowAny) exports active HsmKey objects as EC P-256/RSA JWKs by kid so QR verifiers can validate signatures; SignView (POST /v1/hsm/sign) is service-account only."),
 S("HSM-4 HSM key rotation workflow with overlap and audit", "EVS-HSM", n,
   "High", 5, "Sprint 8", "EVS-HSM phase-3 srs-must HSM-4 rotation", "To Do",
   "SRS-EVS-HSM / HSM-4: HsmKey has valid_from/valid_until/rotated_at fields but no rotation workflow; add scheduled key rotation per purpose with a verification-overlap window and audit events."),
]

# ============ EVS-N05/N08 Observability, SLO, DR, Go-Live ============
n = "EVS-N05 / N08 / N10 — Observability, SLO, DR & Go-Live Readiness"
ROWS += [
 E(n, "EVS-N05", "High", "Sprint 8", "EVS-N05 EVS-N08 EVS-N10 phase-3 srs-must observability dr go-live", "Partial",
   "SRS-EVS-N05/N08/N10: SLO dashboards (verify p95 ≤2 s), DR drills (RTO ≤4 h / RPO ≤1 h), and a go-live gate checklist with an 8-step cutover runbook gate Phase 1 production cutover."),
 S("N08-1 SLO dashboard: verification p95, integrity pass rate, commitment health", "EVS-N05", n,
   "High", 3, "Sprint 8", "EVS-N05 phase-3 srs-must N08-1 slo", "Done",
   "SRS-EVS-N08 / N08-1: GET /v1/ops/slo/dashboard (SLODashboardView) aggregates integrity-sweep pass rate, credential-corpus size and commitment health; extend with the verification p95 ≤2 s histogram."),
 S("N08-2 DR drills: record RTO/RPO against ≤4h / ≤1h targets", "EVS-N05", n,
   "High", 3, "Sprint 8", "EVS-N05 phase-3 srs-must N08-2 dr", "Done",
   "SRS-EVS-N08 / N08-2: DRDrill model + POST /v1/ops/dr-drills capture failover|backup_restore|network_partition drills with rto_seconds/rpo_seconds and a pass flag; GET /{id}/report analyses NFR conformance."),
 S("N10-1 Go-live gate checklist + 8-step cutover runbook (step-up MFA sign-off)", "EVS-N05", n,
   "Medium", 3, "Sprint 8", "EVS-N05 phase-3 srs-must N10-1 go-live", "Done",
   "SRS-EVS-N10 / N10-1: GoLiveGate (open|signed_off) is signed off via POST /v1/programme/go-live-gates/{id}/sign-off (step-up MFA); the cutover runbook at /v1/programme/cutover/runbook unlocks when all gates are signed."),
 S("N08-3 Prometheus/OpenTelemetry metrics and alerting across views and Celery tasks", "EVS-N05", n,
   "Medium", 5, "Sprint 8", "EVS-N05 phase-3 srs-should N08-3 metrics", "To Do",
   "SRS-EVS-N08 / N08-3: there is no metrics/tracing stack; add Prometheus + OpenTelemetry across DRF views and Celery queues (high-priority/normal/sla-monitor/outbox) with alerts on outbox lag, breaker-open and commitment-submit failures."),
 S("N01-DLQ Dead-letter + escalation for failed System 22 commitment submissions", "EVS-N05", n,
   "Medium", 3, "Sprint 8", "EVS-N05 phase-3 srs-should N01-DLQ anchoring", "To Do",
   "SRS-EVS-N01: _submit_commitment_to_s22() retries 3× with 10-min backoff but has no dead-letter queue beyond retry_count; add a DLQ + operator escalation and validate the S22 receipt against the chain head."),
]

if __name__ == "__main__":
    import collections
    print("rows:", len(ROWS),
          "epics:", sum(1 for r in ROWS if r['issue_type']=='Epic'),
          "stories:", sum(1 for r in ROWS if r['issue_type']=='Story'))
    print("status:", dict(collections.Counter(r['status'] for r in ROWS if r['issue_type']=='Story')))
    print("sprints:", dict(collections.Counter(r['sprint'] for r in ROWS if r['issue_type']=='Story')))
