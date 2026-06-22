# Payment Gateway (System 20) Jira backlog rows — derived from /home/user/payments code inventory.
# Mirrors the IAM System19 reference format.

def E(summary, link, name, priority, sprint, labels, status, desc):
    return dict(issue_type="Epic", summary=summary, epic_name=name, epic_link=link,
                priority=priority, story_points=None, sprint=sprint, labels=labels,
                status=status, description=desc)

def S(summary, link, name, priority, sp, sprint, labels, status, desc):
    return dict(issue_type="Story", summary=summary, epic_name=name, epic_link=link,
                priority=priority, story_points=sp, sprint=sprint, labels=labels,
                status=status, description=desc)

ROWS = []

# ===================== PAY-F01 Payment Initiation =====================
n = "PAY-F01 — Payment Initiation & Paystack Checkout"
ROWS += [
 E("PAY-F01 — Payment Initiation & Paystack Checkout", "PAY-F01", n, "Highest", "Sprint 1",
   "PAY-F01 phase-1 srs-must initiate paystack",
   "Partial",
   "SRS-PAY-F01: Consuming systems POST /v1/payments/initiate with a unique PAY-{SYSTEM}-{hex16} reference; gateway calls Paystack /transaction/initialize and returns a hosted checkout authorization_url. Idempotent on reference."),
 S("F01-1 POST /v1/payments/initiate creates Payment and returns Paystack checkout URL", "PAY-F01", n,
   "Highest", 5, "Sprint 1", "PAY-F01 phase-1 srs-must F01-1 initiate", "Done",
   "SRS-PAY-F01 / F01-1: PaymentService.initiate() (app/services/payment_service.py:39) persists a Payment row status=pending and calls PaystackClient.initialize_transaction(); endpoint initiate_payment() at app/api/v1/payments.py:47 returns 201 with authorization_url/access_code."),
 S("F01-2 Idempotent re-submission of an existing reference returns the same checkout URL", "PAY-F01", n,
   "High", 3, "Sprint 1", "PAY-F01 phase-1 srs-must F01-2 idempotency", "Done",
   "SRS-PAY-F01: initiate() checks for an existing Payment by reference and returns the stored paystack_authorization_url with HTTP 200 instead of creating a duplicate; verify 409 path when a reference exists with no checkout URL."),
 S("F01-3 Validate source_system enum and positive amount on initiate", "PAY-F01", n,
   "High", 2, "Sprint 1", "PAY-F01 phase-1 srs-must F01-3 validation", "Done",
   "SRS-PAY-F01: PaymentInitiateRequest (app/schemas/payment.py:13) validators amount_positive() and valid_source_system() enforce amount>0 and source_system in {ams,nlems,nbes,evs,certification}; 422 returned on violation."),
 S("F01-4 Convert GHS to pesewas (x100) when calling Paystack initialize", "PAY-F01", n,
   "Medium", 2, "Sprint 1", "PAY-F01 phase-1 srs-must F01-4 currency", "Done",
   "SRS-PAY-F01: PaystackClient.initialize_transaction() (app/services/paystack/client.py:35) multiplies the GHS Decimal amount by 100 before sending to Paystack; confirm rounding is exact for 2-dp Numeric(12,2) amounts."),
 S("F01-5 Map Paystack/HTTP failures to 502 with structured error envelope", "PAY-F01", n,
   "Medium", 3, "Sprint 1", "PAY-F01 phase-1 srs-must F01-5 errors", "Partial",
   "SRS-PAY-F01: PaystackError (client.py:17) is raised on non-2xx; initiate path should surface HTTP 502 via the errors.py handlers. Add explicit timeout handling for http_timeout_seconds and assert the {detail,status_code} envelope."),
]

# ===================== PAY-F02 Webhook Processing =====================
n = "PAY-F02 — Paystack Webhook Processing & Re-verification"
ROWS += [
 E("PAY-F02 — Paystack Webhook Processing & Re-verification", "PAY-F02", n, "Highest", "Sprint 1",
   "PAY-F02 phase-1 srs-must webhook hmac reverify",
   "Partial",
   "SRS-PAY-F02: Public POST /v1/webhooks/paystack verifies X-Paystack-Signature (HMAC-SHA512 of the raw body), re-verifies charge.success against the Paystack API, sets status confirmed/failed, and is idempotent via the processed_webhooks table."),
 S("F02-1 Verify X-Paystack-Signature HMAC-SHA512 on inbound webhook", "PAY-F02", n,
   "Highest", 3, "Sprint 1", "PAY-F02 phase-1 srs-must F02-1 hmac", "Done",
   "SRS-PAY-F02 / F02-1: PaystackClient.verify_webhook_signature() (client.py:119) computes HMAC-SHA512 over the raw request body with PAYSTACK_SECRET_KEY using hmac.compare_digest(); invalid/missing signature returns 401 when the secret is configured."),
 S("F02-2 Re-verify charge.success with Paystack /transaction/verify before confirming", "PAY-F02", n,
   "Highest", 5, "Sprint 1", "PAY-F02 phase-1 srs-must F02-2 reverify", "Done",
   "SRS-PAY-F02 / F02-2: PaymentService.handle_webhook() (payment_service.py:108) calls PaystackClient.verify_transaction() on charge.success and only sets status=confirmed when the re-verified status is success; captures channel and paystack_transaction_id."),
 S("F02-3 Idempotent webhook processing via processed_webhooks dedupe table", "PAY-F02", n,
   "High", 3, "Sprint 1", "PAY-F02 phase-1 srs-must F02-3 idempotency", "Done",
   "SRS-PAY-F02 / F02-3: ProcessedWebhook (app/db/models.py:60) stores paystack_reference as the idempotency key; a previously processed reference short-circuits to HTTP 200 without reprocessing."),
 S("F02-4 charge.failed sets status=failed and delivers no callback", "PAY-F02", n,
   "High", 2, "Sprint 1", "PAY-F02 phase-1 srs-must F02-4", "Done",
   "SRS-PAY-F02: handle_webhook() sets Payment.status=failed on charge.failed and does not invoke CallbackService.deliver(); all other Paystack event types are acknowledged 200 and ignored."),
 S("F02-5 Harden webhook: 400 on malformed JSON and reject events when secret unset", "PAY-F02", n,
   "Medium", 3, "Sprint 2", "PAY-F02 phase-1 srs-should F02-5 hardening", "Partial",
   "SRS-PAY-F02: paystack_webhook() (app/api/v1/webhooks.py:46) returns 400 on unparseable body; signature check is skipped when PAYSTACK_SECRET_KEY is empty (dev) — add a production guard that fails closed when the secret is absent."),
]

# ===================== PAY-F03 Callback Delivery =====================
n = "PAY-F03 — Signed Callback Delivery to Consuming Systems"
ROWS += [
 E("PAY-F03 — Signed Callback Delivery to Consuming Systems", "PAY-F03", n, "High", "Sprint 2",
   "PAY-F03 phase-1 srs-must callback hmac retry",
   "Partial",
   "SRS-PAY-F03: On confirmation the gateway POSTs a signed (X-Payment-Signature HMAC-SHA256) confirmation to the consuming system callback_url; delivery must be tracked and retried on transient failure."),
 S("F03-1 Deliver signed HMAC-SHA256 callback to callback_url on confirmation", "PAY-F03", n,
   "High", 3, "Sprint 2", "PAY-F03 phase-1 srs-must F03-1 callback", "Done",
   "SRS-PAY-F03 / F03-1: CallbackService.deliver() (app/services/callback_service.py:29) builds the {payment_reference,status,source_system,channel,payer_name,timestamp} payload and signs it with X-Payment-Signature (HMAC-SHA256, CALLBACK_HMAC_SECRET) matching the AMS PaymentWebhookView."),
 S("F03-2 Persist callback_delivered / callback_delivered_at on the Payment", "PAY-F03", n,
   "Medium", 2, "Sprint 2", "PAY-F03 phase-1 srs-must F03-2", "Partial",
   "SRS-PAY-F03 / F03-2: Payment.callback_delivered and callback_delivered_at columns exist (models.py); wire deliver() to set them on a 2xx response so reconciliation can detect undelivered callbacks."),
 S("F03-3 Retry callback delivery with exponential backoff on transient failure", "PAY-F03", n,
   "High", 5, "Sprint 2", "PAY-F03 phase-1 srs-must F03-3 retry", "To Do",
   "SRS-PAY-F03 / F03-3: deliver() is currently fire-and-forget — it returns False on failure with no retry (callback_service.py:29). Add a retry/queue with bounded exponential backoff and a LogoutDeliveryFailure-style audit record on permanent failure."),
 S("F03-4 Manual callback redelivery admin endpoint for missed deliveries", "PAY-F03", n,
   "Medium", 3, "Sprint 3", "PAY-F03 phase-2 srs-should F03-4 redeliver", "To Do",
   "SRS-PAY-F03: No way to re-trigger a callback after a consuming-system outage; add POST /v1/payments/{reference}/redeliver-callback (admin) that re-runs CallbackService.deliver() for confirmed payments with callback_delivered=False."),
]

# ===================== PAY-F04 CALS Financial Compliance =====================
n = "PAY-F04 — CALS Financial Compliance Events & Hash Chain"
ROWS += [
 E("PAY-F04 — CALS Financial Compliance Events & Hash Chain", "PAY-F04", n, "High", "Sprint 2",
   "PAY-F04 phase-1 srs-must cals audit hash-chain",
   "Partial",
   "SRS-PAY-F04: Every confirmed payment emits a masked financial-compliance-v1 event (serviceName=system-20-payment, financialTag=auditor-general) carrying a SHA-256 hash chain (previousHash/currentHash/sequence). CALS-forbidden fields must never be sent."),
 S("F04-1 Post masked payment.confirmed financial event on charge.success", "PAY-F04", n,
   "High", 3, "Sprint 2", "PAY-F04 phase-1 srs-must F04-1 cals", "Done",
   "SRS-PAY-F04 / F04-1: System17Client.report_payment() (app/services/system17.py:100) builds the payment.confirmed event and relays it; it never raises, logging on failure so audit reporting cannot break the payment path."),
 S("F04-2 Strip CALS-forbidden financial fields before relay", "PAY-F04", n,
   "High", 3, "Sprint 2", "PAY-F04 phase-1 srs-must F04-2 masking", "Done",
   "SRS-PAY-F04 / F04-2: _mask_pii() (system17.py:29) removes paymentAmount, transactionId, cardNumber, pan, cvv, accountNumber, iban, routingNumber; add a contract test asserting none of these keys ever appear in the relayed body."),
 S("F04-3 SHA-256 hash chain with CAS chain-tip store (memory + Redis)", "PAY-F04", n,
   "High", 5, "Sprint 2", "PAY-F04 phase-1 srs-must F04-3 chain-store", "Done",
   "SRS-PAY-F04 / F04-3: ChainStore Protocol with InMemoryChainStore and RedisChainStore (app/services/chain_store.py) maintains previousHash/currentHash/sequence per service via compare-and-set; report_payment() advances the tip from the GENESIS hash."),
 S("F04-4 Post directly to CALS /v1/ingest/financial as documented fallback", "PAY-F04", n,
   "Medium", 3, "Sprint 3", "PAY-F04 phase-2 srs-should F04-4 cals-direct", "Partial",
   "SRS-PAY-F04: README/API_REFERENCE specify POST {CALS_URL}/v1/ingest/financial, but events currently route only through the System 17 relay (relay_financial_event(), system17.py:41). Add the direct CALS path gated by CALS_ENABLED/CALS_URL with the same masking and chain."),
 S("F04-5 Stand up Redis chain store in production compose and assert CAS under contention", "PAY-F04", n,
   "Medium", 3, "Sprint 3", "PAY-F04 phase-2 srs-must F04-5 redis", "Partial",
   "SRS-PAY-F04: RedisChainStore exists but CHAIN_STORE defaults to memory; set CHAIN_STORE=redis in prod, point at the redis cache service, and add a concurrency test proving cas_update() rejects a stale expected tip."),
]

# ===================== PAY-F05 Status & Reconciliation =====================
n = "PAY-F05 — Payment Status & Reconciliation API"
ROWS += [
 E("PAY-F05 — Payment Status & Reconciliation API", "PAY-F05", n, "High", "Sprint 2",
   "PAY-F05 phase-1 srs-must status list reconcile",
   "Partial",
   "SRS-PAY-F05: Consuming systems reconcile via GET /v1/payments/{reference}; finance/admin dashboards list and filter payments via GET /v1/payments/ by source_system and status with pagination."),
 S("F05-1 GET /v1/payments/{reference} returns status and metadata", "PAY-F05", n,
   "High", 2, "Sprint 2", "PAY-F05 phase-1 srs-must F05-1 status", "Done",
   "SRS-PAY-F05 / F05-1: PaymentService.get_status() (payment_service.py:167) returns PaymentStatusResponse and raises 404 when the reference is unknown; used by consuming systems to reconcile a missed callback."),
 S("F05-2 GET /v1/payments/ admin list with source_system/status filters", "PAY-F05", n,
   "Medium", 3, "Sprint 2", "PAY-F05 phase-1 srs-must F05-2 list", "Done",
   "SRS-PAY-F05 / F05-2: PaymentService.list_payments() (payment_service.py:173) supports source_system and status filters with limit/offset (1-200)."),
 S("F05-3 Return paginated envelope (data/count/limit/offset) for the list endpoint", "PAY-F05", n,
   "Medium", 2, "Sprint 3", "PAY-F05 phase-2 srs-should F05-3 pagination", "Partial",
   "SRS-PAY-F05 / F05-3: PaymentListResponse (schemas/payment.py) defines data/count/limit/offset but the endpoint returns a raw array (payments.py:92); switch to the envelope so dashboards get a total count."),
]

# ===================== PAY-F06 Lifecycle & Expiry =====================
n = "PAY-F06 — Payment Lifecycle & Abandoned-Payment Expiry"
ROWS += [
 E("PAY-F06 — Payment Lifecycle & Abandoned-Payment Expiry", "PAY-F06", n, "High", "Sprint 3",
   "PAY-F06 phase-2 srs-must lifecycle expiry scheduler",
   "To Do",
   "SRS-PAY-F06: Payment status lifecycle pending -> confirmed/failed/abandoned. A scheduled expiry job must transition stale pending payments to abandoned; no background scheduler exists today."),
 S("F06-1 expire_stale_payments job marks pending checkouts abandoned after timeout", "PAY-F06", n,
   "High", 5, "Sprint 3", "PAY-F06 phase-2 srs-must F06-1 expiry", "To Do",
   "SRS-PAY-F06 / F06-1: README (L172) and API_REFERENCE (L47) promise a 'future expiry job' but none exists — payments stay pending forever. Add a scheduled task (Celery/APScheduler) that sets status=abandoned for pending payments older than the configured checkout TTL."),
 S("F06-2 Introduce a background scheduler/worker for periodic jobs", "PAY-F06", n,
   "High", 5, "Sprint 3", "PAY-F06 phase-2 srs-must F06-2 scheduler", "To Do",
   "SRS-PAY-F06 / F06-2: requirements.txt has no Celery/APScheduler; add a worker process (reusing the redis cache service as broker) to host the expiry sweep and callback-retry queue."),
 S("F06-3 Emit payment.abandoned reconciliation event/audit when a payment expires", "PAY-F06", n,
   "Medium", 3, "Sprint 4", "PAY-F06 phase-2 srs-should F06-3", "To Do",
   "SRS-PAY-F06 / F06-3: When expire_stale_payments transitions a row to abandoned, record an audit/CALS event so finance can distinguish abandoned from failed payments in reconciliation."),
]

# ===================== PAY-N01 Security & Auth =====================
n = "PAY-N01 — API Authentication, Rate Limiting & Secrets"
ROWS += [
 E("PAY-N01 — API Authentication, Rate Limiting & Secrets", "PAY-N01", n, "High", "Sprint 4",
   "PAY-N01 phase-1 srs-must auth rate-limit secrets",
   "Partial",
   "SRS-PAY-N01: All /v1/payments endpoints require a pre-shared Bearer PAYMENT_API_KEY; the public webhook is HMAC-gated; abuse is bounded by rate limiting and secrets fail closed in production."),
 S("N01-1 Bearer API-key auth dependency on all payment endpoints", "PAY-N01", n,
   "High", 3, "Sprint 4", "PAY-N01 phase-1 srs-must N01-1 api-key", "Done",
   "SRS-PAY-N01 / N01-1: require_api_key() (app/core/dependencies.py:27) validates the Authorization Bearer token against PAYMENT_API_KEY and returns 401 on mismatch; it is wired into the payments router."),
 S("N01-2 Fail closed when PAYMENT_API_KEY / PAYSTACK_SECRET_KEY unset in production", "PAY-N01", n,
   "High", 3, "Sprint 4", "PAY-N01 phase-1 srs-must N01-2 fail-closed", "To Do",
   "SRS-PAY-N01 / N01-2: require_api_key() and webhook verification silently skip when their secrets are empty (dev convenience); add a production startup guard that raises if PAYMENT_API_KEY, PAYSTACK_SECRET_KEY or CALLBACK_HMAC_SECRET is missing."),
 S("N01-3 Enforce per-source rate limiting on initiate and webhook", "PAY-N01", n,
   "Medium", 5, "Sprint 4", "PAY-N01 phase-2 srs-should N01-3 rate-limit", "To Do",
   "SRS-PAY-N01 / N01-3: Settings.rate_limit_enabled (config.py:40) exists but is never read; implement Redis-backed rate limiting middleware for /v1/payments/initiate and the webhook to bound abuse."),
]

# ===================== PAY-N02 Persistence & Migrations =====================
n = "PAY-N02 — Data Persistence & Schema Migrations"
ROWS += [
 E("PAY-N02 — Data Persistence & Schema Migrations", "PAY-N02", n, "High", "Sprint 4",
   "PAY-N02 phase-1 srs-must persistence alembic",
   "Partial",
   "SRS-PAY-N02: Payment and ProcessedWebhook are stored in a dedicated PostgreSQL instance; production schema changes must be applied through versioned Alembic migrations, not auto-create."),
 S("N02-1 Replace Base.metadata.create_all bootstrap with Alembic migrations", "PAY-N02", n,
   "High", 5, "Sprint 4", "PAY-N02 phase-1 srs-must N02-1 alembic", "To Do",
   "SRS-PAY-N02 / N02-1: init_db() (app/db/base.py:19) auto-creates tables on startup and a comment notes Alembic should be used in production; add alembic.ini + env.py + an initial migration covering payments and processed_webhooks and gate it in CI."),
 S("N02-2 Add indexes/constraints for reconciliation queries", "PAY-N02", n,
   "Medium", 2, "Sprint 4", "PAY-N02 phase-2 srs-should N02-2 indexes", "Partial",
   "SRS-PAY-N02 / N02-2: reference and paystack_reference are unique-indexed; add composite indexes on (source_system,status,created_at) to keep the admin list endpoint fast as volume grows."),
]

# ===================== PAY-N03 Tests & Contracts =====================
n = "PAY-N03 — Test Coverage & Contract Tests"
ROWS += [
 E("PAY-N03 — Test Coverage & Contract Tests", "PAY-N03", n, "High", "Sprint 5",
   "PAY-N03 phase-1 srs-must testing contracts ci",
   "To Do",
   "SRS-PAY-N03: Beyond the 3 smoke tests, the gateway needs full coverage of the payment flow, webhook idempotency, signature verification, callback delivery, and CALS masking, plus OpenAPI contract tests in CI."),
 S("N03-1 Integration tests for initiate -> webhook -> callback happy path", "PAY-N03", n,
   "High", 5, "Sprint 5", "PAY-N03 phase-1 srs-must N03-1 integration", "To Do",
   "SRS-PAY-N03 / N03-1: tests/ contains only test_health.py (3 smoke tests). Add an end-to-end test with a mocked Paystack covering initiate, charge.success webhook, re-verification, confirmation, and signed callback delivery."),
 S("N03-2 Tests for webhook idempotency and HMAC-SHA512/256 signatures", "PAY-N03", n,
   "High", 3, "Sprint 5", "PAY-N03 phase-1 srs-must N03-2 security-tests", "To Do",
   "SRS-PAY-N03 / N03-2: No tests assert duplicate-webhook dedupe via processed_webhooks, reject a bad X-Paystack-Signature, or verify the outbound X-Payment-Signature. Add them as security regression tests."),
 S("N03-3 CALS masking contract test: forbidden fields never relayed", "PAY-N03", n,
   "Medium", 3, "Sprint 5", "PAY-N03 phase-1 srs-must N03-3 cals-contract", "To Do",
   "SRS-PAY-N03 / N03-3: Add a test that captures the relayed System 17/CALS body and asserts none of the eight forbidden financial fields appear, and that previousHash/currentHash/sequence advance correctly."),
 S("N03-4 Wire the pytest acceptance marker into CI with real scenarios", "PAY-N03", n,
   "Medium", 2, "Sprint 5", "PAY-N03 phase-2 srs-should N03-4 acceptance", "To Do",
   "SRS-PAY-N03 / N03-4: pyproject.toml defines an 'acceptance' marker but no acceptance tests exist; author System 17 relay acceptance scenarios and run them as a separate CI stage."),
]

# ===================== PAY-N04 Observability & Deployment =====================
n = "PAY-N04 — Observability, Deployment & Operations"
ROWS += [
 E("PAY-N04 — Observability, Deployment & Operations", "PAY-N04", n, "Medium", "Sprint 6",
   "PAY-N04 phase-2 srs-should observability deploy",
   "Partial",
   "SRS-PAY-N04: CI builds and deploys the gateway image; production needs structured metrics, health/readiness probes, and alerting on Paystack/CALS failures and stuck pending payments."),
 S("N04-1 CI pipeline: pytest + ruff + bandit, GHCR image, VPS deploy", "PAY-N04", n,
   "Medium", 3, "Sprint 6", "PAY-N04 phase-1 srs-must N04-1 ci", "Done",
   "SRS-PAY-N04 / N04-1: .github/workflows/ci.yml runs the test job (Postgres+Redis services, ruff, bandit), builds ghcr.io/rfd-tech/payment-api and deploys to the VPS on dev push; tighten the pytest exit-code-5 allowance once real tests land."),
 S("N04-2 Add /v1/health readiness probe that checks DB and Redis", "PAY-N04", n,
   "Medium", 2, "Sprint 6", "PAY-N04 phase-2 srs-should N04-2 readiness", "Partial",
   "SRS-PAY-N04 / N04-2: GET /v1/health is liveness-only and does not check DB connectivity (health.py); add a readiness endpoint that verifies the Postgres session and Redis chain store before reporting ready."),
 S("N04-3 Prometheus metrics and alerts for Paystack/CALS failures and stuck pending payments", "PAY-N04", n,
   "Medium", 5, "Sprint 6", "PAY-N04 phase-2 srs-should N04-3 metrics", "To Do",
   "SRS-PAY-N04 / N04-3: No metrics are exported; add counters for initiate/confirm/fail, callback delivery outcomes, CALS relay failures, and a gauge for pending-payment age so operators can alert on stuck checkouts."),
 S("N04-4 Structured request/audit logging with trace_id propagation", "PAY-N04", n,
   "Medium", 3, "Sprint 6", "PAY-N04 phase-2 srs-should N04-4 logging", "Partial",
   "SRS-PAY-N04 / N04-4: report_payment() generates a traceId for CALS events; extend structured logging across initiate and webhook handlers so a single trace_id links a payment from initiate through confirmation, callback, and CALS relay."),
]

if __name__ == "__main__":
    import collections
    print("rows:", len(ROWS),
          "epics:", sum(1 for r in ROWS if r['issue_type']=='Epic'),
          "stories:", sum(1 for r in ROWS if r['issue_type']=='Story'))
    by = collections.Counter(r['status'] for r in ROWS if r['issue_type']=='Story')
    print("status:", dict(by))
