# Jira Backlogs — EVS (System 03) & Payment Gateway (System 20)

Jira-importable backlogs reverse-engineered from the two codebases, in the same
format as the IAM (System 19) reference backlog. Each **Story** maps to a real
code artifact (model, endpoint, service, Celery task, or stub) and carries an
implementation status assessed from the source:

| Status | Meaning |
|--------|---------|
| **Done** | Implemented and wired end-to-end in the codebase. |
| **Partial** | Present but incomplete — a stub, missing branch, hardcoded value, or unwired path. |
| **To Do** | Promised by the README/API contract but not implemented. |

## Files

| File | Source codebase |
|------|-----------------|
| `EVS_System03_Jira_Backlog.xlsx` | `RFD-TECH/evs-backend` (Django) — 15 epics / 65 stories |
| `Payments_System20_Jira_Backlog.xlsx` | `RFD-TECH/payments` (FastAPI) — 10 epics / 38 stories |

Each workbook has two sheets:
- **Backlog** — `Issue Type, Summary, Epic Name, Epic Link, Priority, Story Points, Sprint, Labels, Status, Description`
- **Sprint Summary** — per-sprint story count, points, Done count and % complete (computed).

## Regenerating

The workbooks are generated deterministically from Python row definitions:

```bash
cd docs/jira-backlog
python3 -c "import gen_backlog, evs_rows, payments_rows; \
  gen_backlog.build(evs_rows.ROWS, 'EVS_System03_Jira_Backlog.xlsx', 'EVS Backlog'); \
  gen_backlog.build(payments_rows.ROWS, 'Payments_System20_Jira_Backlog.xlsx', 'Payments Backlog')"
```

- `gen_backlog.py` — styling + Sprint Summary generator (matches the IAM reference palette).
- `evs_rows.py` / `payments_rows.py` — the backlog rows, with file/line citations into each codebase.

Requires `openpyxl`.
