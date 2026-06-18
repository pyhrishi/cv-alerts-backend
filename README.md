# Cisco Cyber Vision — New Alert Framework (Backend + System of Record)

This repository is the **system of record** for the Cisco TPM (AI Builder) exercise: a
standalone, interactive alerts experience backed by **live Cyber Vision data**. It holds the
backend service, the alert engine, **and all project documentation** (assignment digest,
architecture, API findings, alert spec, deliverables checklist).

The dashboard UI lives in a separate repo — **[cv-alerts-frontend](https://github.com/pyhrishi/cv-alerts-frontend)** — and talks only to this backend, never to the Cyber Vision Center directly.

## Layout
```
cv-alerts-backend/            # this repo (deploys to Render)
  app/
    models.py                 # Pydantic: Asset, Activity, Alert, GraphNode, GraphEdge
    cv_client.py              # the ONLY place that calls Cyber Vision (httpx, verify=False)
    alerts/
      operations.py           # "asset went silent"        (pure detection fn)
      security.py             # "cross-zone violation"      (pure, reads the policy)
      custom.py               # "vulnerable-asset exposure" (pure detection fn)
    policy/
      expected_state_policy.yaml   # our authored OT baseline (security alert's brain)
  scripts/
    discover*.py              # Phase-1 API discovery probes
    fetch_samples.py          # dump full real datasets to docs/api-samples/*.raw.json (local)
    run_alerts_offline.py     # run all three detectors over saved samples (or --live)
  tests/                      # pytest, fixtures built from real trimmed samples
  docs/
    ASSIGNMENT.md  ARCHITECTURE.md  API-FINDINGS.md  ALERT-SPEC.md
    DELIVERABLES-CHECKLIST.md  BACKEND-NOTES.md  api-samples/  prompts/
  .claude/                    # Claude Code config: skills, agents, slash commands
  CLAUDE.md                   # project memory / instructions
```

## How we work
A human PM drives via prioritized prompts; one phase is executed and reviewed at a time:
1. API discovery → 2. data + alert design (**current**) → 3. backend API → 4. frontend → 5. deploy → 6. docs.

## Quick start (Phase 2 — offline alert engine, no server yet)
```bash
python -m venv .venv && .venv/Scripts/python -m pip install -r requirements.txt
cp .env.example .env            # fill in CV_BASE_URL + CV_API_TOKEN (never commit .env)
.venv/Scripts/python scripts/run_alerts_offline.py          # runs over saved samples
.venv/Scripts/python scripts/run_alerts_offline.py --live   # pulls fresh from the Center
.venv/Scripts/python -m pytest -q                           # unit tests for all three alerts
```

## Security
No credentials live in git. They go in a local `.env` (gitignored) and the Render dashboard.
See `.env.example` for variable names. `verify=False` (self-signed cert) is isolated to
`app/cv_client.py` and is **exercise-only**.

## Key docs
- [docs/API-FINDINGS.md](docs/API-FINDINGS.md) — what the live CV API returns and which alerts the data supports.
- [docs/ALERT-SPEC.md](docs/ALERT-SPEC.md) — full contract for all three alerts (trigger, severity rule, evidence, compliance).
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — design + tradeoffs.
- [docs/DELIVERABLES-CHECKLIST.md](docs/DELIVERABLES-CHECKLIST.md) — submission tracker.
