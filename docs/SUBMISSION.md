# Submission — Cisco Cyber Vision New Alert Experience

A standalone, interactive **OT/ICS alert dashboard** for Cisco Cyber Vision, backed by data pulled
**programmatically via the Center API**. Three new alerts (Security · Operations · Vulnerability
exposure), a communication-relations graph, and tabular + visual reports.

## Live demo
| | URL |
|---|---|
| **Dashboard (frontend)** | https://cv-alerts-frontend.vercel.app |
| **API (backend)** | https://cv-alerts-backend-1.onrender.com — try `/healthz`, `/kpis`, `/alerts`, `/graph` |

> ⏳ **First load may take ~30–60 seconds.** Both run on free tiers that sleep when idle; the first
> request wakes them. The dashboard shows a **"Waking the backend…"** state during this and recovers
> automatically — it is not a failure. Subsequent loads are immediate.

> 🟡 **The public demo runs in "snapshot" mode** — it serves a frozen, bundled copy of the
> Cisco-provided sandbox dataset and **never connects to the live Center**, so no OT credential is
> exposed on a public URL. The badge top-left reads **"Snapshot"** to make this explicit. The full
> live proxy (`DATA_MODE=live`, token server-side) is what runs locally against the Center. Rationale:
> [`ARCHITECTURE.md`](ARCHITECTURE.md) and [`DESIGN-CHOICES.md`](DESIGN-CHOICES.md).

## Repositories
| Repo | Purpose |
|---|---|
| **Backend + system of record** — https://github.com/pyhrishi/cv-alerts-backend | FastAPI proxy + alert engine, the policy, tests, **and all documentation** |
| **Frontend** — https://github.com/pyhrishi/cv-alerts-frontend | Next.js + TypeScript + Tailwind dashboard (talks only to the backend) |

## Where each deliverable lives
| Deliverable (from the brief) | Where |
|---|---|
| Programmatic API connection (key server-side) | `app/cv_client.py`, `app/config.py`; discovery in `scripts/discover*.py` |
| What the API returns / which alerts the data supports | [`docs/API-FINDINGS.md`](API-FINDINGS.md) |
| The three alerts — full contract (trigger, severity rule, evidence, compliance) | [`docs/ALERT-SPEC.md`](ALERT-SPEC.md) |
| Alert detection logic (pure, typed) | `app/alerts/operations.py`, `security.py`, `custom.py`; `app/models.py` |
| Authored expected-state policy (the security alert's "brain") | `app/policy/expected_state_policy.yaml` |
| Communication-relations visualization | frontend `components/GraphCanvas.tsx` (Cytoscape, Purdue zones) |
| Standalone interactive dashboard (Alerts centerpiece) | https://cv-alerts-frontend.vercel.app |
| Tabular report (+ CSV / print) | dashboard **Report** tab; `components/ReportsTable.tsx` |
| Visual reports (KPIs, trends) | dashboard **KPI strip** + **Trends** tab (Recharts) |
| Design choices + intended audience | [`docs/DESIGN-CHOICES.md`](DESIGN-CHOICES.md) |
| Architecture / design notes + tradeoffs | [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) |
| Non-obvious problems solved (engineering depth) | [`docs/ENGINEERING-NOTES.md`](ENGINEERING-NOTES.md) |
| Creativity — chosen extensions + future work | [`docs/CREATIVITY.md`](CREATIVITY.md) |
| Unit tests (per alert + API contract) | `tests/` — `pytest -q` (21 tests) |
| Setup / run / test instructions | each repo's `README.md` |
| Deliverables cross-check | [`docs/DELIVERABLES-CHECKLIST.md`](DELIVERABLES-CHECKLIST.md) |

## 60-second local run (full live mode against the Center)
```bash
# backend
git clone https://github.com/pyhrishi/cv-alerts-backend && cd cv-alerts-backend
python -m venv .venv && .venv/Scripts/python -m pip install -r requirements.txt   # (use .venv/bin on macOS/Linux)
cp .env.example .env            # fill CV_BASE_URL + CV_API_TOKEN, set DATA_MODE=live
.venv/Scripts/python -m pytest -q                                   # 21 tests
.venv/Scripts/python -m uvicorn app.main:app --port 8000            # API on :8000

# frontend (second terminal)
git clone https://github.com/pyhrishi/cv-alerts-frontend && cd cv-alerts-frontend
npm install
echo "NEXT_PUBLIC_API_BASE_URL=http://localhost:8000" > .env.local
npm run dev                                                          # dashboard on :3000
```
Omit `DATA_MODE`/token to run the backend in safe **snapshot** mode with no Center connection.
