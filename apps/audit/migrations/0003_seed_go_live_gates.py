"""Phase 10 — Seed the initial Go-Live gate checklist items.

These gates must all be signed off before the cutover runbook is unlocked.
Each gate maps to a specific Phase 10 readiness criterion from the EVS Volume III-B spec.
"""
from django.db import migrations


INITIAL_GATES = [
    {
        "gate_id": "phase9-integrity-sweep-passed",
        "title": "Phase 9 — Nightly integrity sweep passes with 0 tampered credentials",
        "description": "Run the nightly integrity sweep against the full production credential corpus and confirm tampered_count == 0 in the IntegrityRun record.",
        "owner_role": "system_administrator",
        "display_order": 1,
    },
    {
        "gate_id": "daily-commitment-chain-verified",
        "title": "Phase 9 — Daily commitment chain verified for 7 consecutive days",
        "description": "All DailyCommitment records for the last 7 days are in 'confirmed' status with valid chain_valid == True.",
        "owner_role": "system_administrator",
        "display_order": 2,
    },
    {
        "gate_id": "ag-export-smoke-test",
        "title": "Phase 9 — Auditor-General export bundle smoke test passed",
        "description": "Generate a 30-day AG export, download the ZIP, and verify bundle integrity using verify.md.",
        "owner_role": "auditor_general",
        "display_order": 3,
    },
    {
        "gate_id": "tiered-retention-config-verified",
        "title": "Phase 9 — Tiered retention MinIO buckets provisioned and tested",
        "description": "Confirm evs-exports and evs-cold-archive MinIO buckets are accessible and a test JSONL archive upload succeeds.",
        "owner_role": "system_administrator",
        "display_order": 4,
    },
    {
        "gate_id": "dr-failover-passed",
        "title": "Phase 10 — DR database failover drill passed (RTO ≤ 4h, RPO ≤ 1h)",
        "description": "A DRDrill record of type 'failover' must exist with passed == True.",
        "owner_role": "programme_manager",
        "display_order": 5,
    },
    {
        "gate_id": "dr-backup-restore-passed",
        "title": "Phase 10 — DR backup restore drill passed",
        "description": "A DRDrill record of type 'backup_restore' must exist with passed == True.",
        "owner_role": "programme_manager",
        "display_order": 6,
    },
    {
        "gate_id": "nfr-slo-baseline-established",
        "title": "Phase 10 — NFR SLO baseline established (p95 verification latency < 2s)",
        "description": "Review SLO dashboard and confirm verification endpoint p95 latency is under the 2-second NFR target.",
        "owner_role": "system_administrator",
        "display_order": 7,
    },
    {
        "gate_id": "uat-acceptance-signed-off",
        "title": "Phase 10 — UAT acceptance sign-off by Registrar",
        "description": "The Registrar has completed UAT test scenarios and signed off acceptance in writing.",
        "owner_role": "registrar",
        "display_order": 8,
    },
    {
        "gate_id": "security-pen-test-cleared",
        "title": "Phase 10 — Security penetration test — no critical findings",
        "description": "External pen test report shows zero critical or high-severity findings outstanding.",
        "owner_role": "system_administrator",
        "display_order": 9,
    },
    {
        "gate_id": "programme-director-cutover-approval",
        "title": "Phase 10 — Programme Director approves go-live cutover",
        "description": "Final approval from the Programme Director to proceed with DNS cutover and production launch.",
        "owner_role": "programme_manager",
        "display_order": 10,
    },
]


def seed_forward(apps, schema_editor):
    GoLiveGate = apps.get_model("audit", "GoLiveGate")
    for gate_data in INITIAL_GATES:
        GoLiveGate.objects.get_or_create(
            gate_id=gate_data["gate_id"],
            defaults={k: v for k, v in gate_data.items() if k != "gate_id"},
        )


def seed_reverse(apps, schema_editor):
    GoLiveGate = apps.get_model("audit", "GoLiveGate")
    gate_ids = [g["gate_id"] for g in INITIAL_GATES]
    GoLiveGate.objects.filter(gate_id__in=gate_ids).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("audit", "0002_phase9_10_models"),
    ]

    operations = [
        migrations.RunPython(seed_forward, seed_reverse),
    ]
