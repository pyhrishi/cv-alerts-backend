# Cisco Cyber Vision — Alert Backend (+ System of Record)

FastAPI **secure proxy + alert engine** in front of a Cisco Cyber Vision OT/ICS Center. It pulls data
programmatically from the Center, normalizes it into typed models, computes **three alerts**
(Security · Operations · Vulnerability exposure), and exposes a clean REST API. This repo is also the
**system of record** — it holds all project documentation.

The dashboard UI is a separate repo — **[cv-alerts-frontend](https://github.com/pyhrishi/cv-alerts-frontend)** — and talks only to this backend, never to the Center.

## Live
- **Dashboard:** https://cv-alerts-frontend.vercel.app
- **API:** https://cv-alerts-backend-1.onrender.com — `/healthz`, `/kpis`, `/alerts`, `/assets`, `/graph`

> ⏳ **Free-tier cold start:** the first request after idle can take **~30–60s** to wake. Not a failure —
> the dashboard shows a "Waking the backend…" state and recovers automatically.

## Snapshot vs. live (`DATA_MODE`)
- **`snapshot` (default; what the public demo runs):** serves a frozen, bundled copy of the sandbox data
  (`docs/api-samples/*.snapshot.json`) and **never connects to the Center** — no token required. Safe for a
  public URL (no live OT telemetry, no secret exposed). The `data_source` field/badge reads **"snapshot."**
- **`live`:** calls the Center (needs `CV_BASE_URL` + `CV_API_TOKEN`), falls back to snapshot if unreachable.

Rationale in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/DESIGN-CHOICES.md`](docs/DESIGN-CHOICES.md).

## Endpoints
| Route | Returns |
|---|---|
| `GET /healthz` | `{"status":"ok"}` (liveness; never calls the Center) |
| `GET /assets` | normalized inventory (id, name, ip, mac, vendor, purdue_level, cve_count, max_cvss) |
| `GET /alerts?category=&severity=` | all three alert types as `Alert` objects (filterable) |
| `GET /graph` | Cytoscape-ready nodes/edges; each carries the alert ids that implicate it |
| `GET /kpis` | counts by severity/category, silent/cross-zone/vulnerable, `reference_now` |

Every response carries `data_source: "live" | "snapshot"`.

## Setup / run / test (from a fresh clone)
Requires Python 3.11+ (developed on 3.14). Use `.venv/Scripts/...` on Windows, `.venv/bin/...` on macOS/Linux.
```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt

# tests — 21 unit tests (per-alert detection + API contract), no network needed
.venv/Scripts/python -m pytest -q

# run the three detectors over the bundled snapshot and print a summary table
.venv/Scripts/python scripts/run_alerts_offline.py
#   add --live to pull fresh from the Center (requires .env below)

# run the API (snapshot mode by default — no token needed)
.venv/Scripts/python -m uvicorn app.main:app --port 8000
#   -> http://localhost:8000/kpis , /alerts , /graph , /healthz
```

### Live mode against the Center (optional)
```bash
cp .env.example .env     # set CV_BASE_URL, CV_API_TOKEN, DATA_MODE=live, ALLOWED_ORIGINS
.venv/Scripts/python -m uvicorn app.main:app --port 8000
```
`.env` is gitignored — never commit it. `verify=False` (self-signed CV cert) is isolated to
`app/cv_client.py` and flagged exercise-only.

## Layout
```
app/
  main.py        # FastAPI app, CORS (locked to ALLOWED_ORIGINS), the 5 routes
  config.py      # env loading (CV_BASE_URL, CV_API_TOKEN, ALLOWED_ORIGINS, DATA_MODE, CACHE_TTL)
  cv_client.py   # the ONLY caller of Cyber Vision (x-token-id, /api/3.0; verify=False isolated here)
  cache.py       # TTL cache (default 60s) so the Center is never hit per browser request
  service.py     # builds the cached bundle: fetch -> parse -> run detectors (+ snapshot fallback)
  models.py      # Pydantic: Asset, Activity, Vulnerability, Alert, Graph*, Policy
  graph.py       # Cytoscape transform; lands alerts on nodes/edges by IP/MAC
  alerts/
    operations.py  security.py  custom.py   # three pure detection functions
  policy/expected_state_policy.yaml          # authored OT baseline (the security alert's brain)
scripts/   discover*.py · fetch_samples.py · run_alerts_offline.py
tests/     test_operations · test_security · test_custom · test_api      (21 tests)
render.yaml   docs/   .env.example
```

## Documentation (this repo is the system of record)
- [`docs/SUBMISSION.md`](docs/SUBMISSION.md) — one-page index: links, live URLs, where every deliverable lives.
- [`docs/DESIGN-CHOICES.md`](docs/DESIGN-CHOICES.md) — audience + design narrative (required deliverable).
- [`docs/API-FINDINGS.md`](docs/API-FINDINGS.md) — what the live CV API returns; which alerts the data supports.
- [`docs/ALERT-SPEC.md`](docs/ALERT-SPEC.md) — full contract for all three alerts (trigger, severity rule, evidence, compliance).
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — design, tradeoffs, snapshot/live rationale.
- [`docs/ENGINEERING-NOTES.md`](docs/ENGINEERING-NOTES.md) — non-obvious problems solved.
- [`docs/CREATIVITY.md`](docs/CREATIVITY.md) — chosen extensions + future work.
- [`docs/DELIVERABLES-CHECKLIST.md`](docs/DELIVERABLES-CHECKLIST.md) — cross-check against the brief.
