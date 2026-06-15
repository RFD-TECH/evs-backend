# EVS — Examination Verification System (System 03)

Cryptographic credential verification service for the Council for Legal Education and Training (CLET). EVS issues QR-coded, HSM-signed credentials and provides multi-channel verification (QR scan, PDF PAdES, uploaded-QR, WAEC API, and foreign credential assessment).

## Stack

| Component | Technology |
|---|---|
| Runtime | Python 3.12 / Django 5 / DRF |
| Task queue | Celery + Redis |
| Database | PostgreSQL 15 |
| Identity | Keycloak (`clet-internal` + `institutions` realms) |
| HSM | SoftHSM2 (dev) / PKCS#11 (prod) |
| Messaging | System 17 relay → Kafka |

## Service Ports (dev)

| Service | Port |
|---|---|
| EVS API | 8003 |
| PostgreSQL | 5435 |
| Redis | 6382 |

## Quick Start

```bash
cp .env.example .env          # fill in secrets
docker compose up -d
docker compose exec web python manage.py migrate
docker compose exec web python manage.py createsuperuser
```

## Verification Channels

| Channel | Endpoint | Feature |
|---|---|---|
| QR Scan | `GET /v1/verify/{uuid}?token=` | F05 — real-time, public, ≤2 s |
| PDF Upload | `POST /v1/verify/pdf` | F06 — PAdES B-T/B-LT/B-LTA |
| Uploaded QR | `POST /v1/verify/uploaded-qr` | F07 — decode QR from image/PDF |
| WAEC API | `POST /v1/verify/waec` | F04 — external WAEC grade check |
| Foreign Cred | `POST /v1/foreign-credentials/` | F03 — 11-stage FCA workflow |

## Roles

| Role | Type | Key Permissions |
|---|---|---|
| `system_administrator` | Internal | All 20 permissions |
| `registrar` | Internal | Credential manage, vault, queue |
| `verification_officer` | Internal | credential:read, WAEC |
| `institution_officer` | External | bulk:ingest, credential:read |
| `candidate` | External | credential:read, FCA apply |
| `assessor` | Internal | FCA read + assess |
| `director_general` | Internal | FCA read + sign (HSM) |

## IAM Integration

Roles are assigned by IAM (System 19) as Keycloak client roles on the `evs-api` client. EVS reads `resource_access["evs-api"]["roles"]` from the JWT — it does not manage role assignments. The local `Role` and `RolePermission` tables are EVS-owned permission matrices only.

## Upstream Integrations

| System | Purpose |
|---|---|
| System 17 (API Layer) | Relay all `AuditEvent` rows to CALS; Kafka event bus |
| System 22 (CALS) | Hash-chain anchors; daily `DailyHashAnchor` |
| System 21 (Notifications) | SLA reminders, revocation alerts, FCA decision dispatch |
| Keycloak | RS256 JWT auth; JWKS endpoint |
| WAEC API | External certificate grade verification |

## Branch Strategy

| Branch | Purpose |
|---|---|
| `main` | Production |
| `staging` | Pre-production |
| `dev` | Integration (default) |
| `feat/phase-*` | Feature branches — PR into `dev` in order |

Feature branches are stacked: merge Phase N before opening the Phase N+1 PR, so each PR shows only the incremental diff.
