# Deliverables Checklist (cross-checked against the assignment)

Each item notes **where it is satisfied** (file / URL). Anything partial is flagged honestly.
Live: dashboard https://cv-alerts-frontend.vercel.app · API https://cv-alerts-backend-1.onrender.com

## Mandatory
- [x] **Programmatic API connection to CV center (key server-side only)** — `app/cv_client.py`
  (auth `x-token-id`, `/api/3.0`), `app/config.py`; token only server-side. Discovery: `scripts/discover*.py`.
- [x] **Data fetched from CV (inventory, flows, vulnerabilities, events)** — inventory (`/components`, 180),
  comms (`/activities`, 300), vulnerabilities (per-component CVEs, 45 assets). ⚠️ **Honest note:** on this
  instance `/flows` is empty (we use the populated `/activities` layer) and `events` / `baselines` /
  `groups` are **empty or absent** — documented in [`API-FINDINGS.md`](API-FINDINGS.md). We compensated by
  **authoring an explicit expected-state policy** instead of relying on native CV events.
- [x] **Alert 1 — Security (real data)** — "cross-zone / unauthorized comms", `app/alerts/security.py`,
  policy-driven; 18 firing. Spec: [`ALERT-SPEC.md`](ALERT-SPEC.md).
- [x] **Alert 2 — Operations (real data)** — "asset went silent" (subnet-median), `app/alerts/operations.py`; 5 firing.
- [x] **Alert 3 — Free choice (justified, real data)** — "vulnerable asset exposure" (CVE × reachability ×
  criticality), `app/alerts/custom.py`; 15 firing. Rationale: [`DESIGN-CHOICES.md`](DESIGN-CHOICES.md).
- [x] **Communication-relations visualization** — Cytoscape Purdue-layered graph with alert blast-radius
  highlight: frontend `components/GraphCanvas.tsx`; served by `/graph` (`app/graph.py`).
- [x] **Standalone interactive dashboard (Alerts centerpiece)** — https://cv-alerts-frontend.vercel.app
  (Alerts list + detail, graph, report, trends).
- [x] **Tabular and/or visual report** — **Report** tab (sortable table + copy-CSV + print,
  `components/ReportsTable.tsx`) plus KPI strip and **Trends** (Recharts).
- [x] **Two git repos, clean history** — backend + frontend; history audited (no `.env`, no GitHub/CV token,
  no password in either repo's history).
- [x] **Deployed: backend on Render, frontend on Vercel (live URLs)** — both live and verified
  end-to-end (snapshot badge, CORS locked to the Vercel origin, alert→graph highlight working).

## Documentation
- [x] **README per repo: setup, run, test (fresh clone)** — `cv-alerts-backend/README.md`,
  `cv-alerts-frontend/README.md`; commands traced this session (pytest 21 green, `npm run build` clean).
- [x] **Architecture / design notes** — [`ARCHITECTURE.md`](ARCHITECTURE.md).
- [x] **Written design-choices + intended-audience explanation** — [`DESIGN-CHOICES.md`](DESIGN-CHOICES.md).
- [x] **Assumptions + tradeoffs documented** — [`ALERT-SPEC.md`](ALERT-SPEC.md) (assumptions),
  [`ARCHITECTURE.md`](ARCHITECTURE.md) + [`CREATIVITY.md`](CREATIVITY.md) (tradeoffs).
- [x] **Limitations / incomplete areas stated transparently** — [`API-FINDINGS.md`](API-FINDINGS.md)
  (empty events/baselines/groups), [`ALERT-SPEC.md`](ALERT-SPEC.md) (static-capture caveat),
  [`ENGINEERING-NOTES.md`](ENGINEERING-NOTES.md), and the future-work list in [`CREATIVITY.md`](CREATIVITY.md).
- [x] **Testing instructions** — READMEs + [`SUBMISSION.md`](SUBMISSION.md) (`pytest -q`; `npm run build`).

## Engineering practices
- [x] **Unit tests for each alert's detection logic** — `tests/test_operations.py`, `test_security.py`,
  `test_custom.py` (fire / no-fire / severity-derivation) + `tests/test_api.py` (API contract). **21 passing.**
- [x] **No secrets in git; .env.example present; .gitignore correct** — both repos have `.env.example`
  (names only); `.env`/`.env.local` and `*.raw.json` gitignored; history audited clean.
- [x] **Typed models (Pydantic + shared TS interfaces)** — `app/models.py` (Pydantic) mirrored by
  `lib/types.ts` (frontend).

## Creativity (optional)
- [x] **Chosen extension(s) implemented** — exposure-fusion alert, alert→graph blast-radius highlight,
  `DATA_MODE` snapshot/live safety toggle, resilience fallback + cold-start UX. See [`CREATIVITY.md`](CREATIVITY.md).
- [x] **Rationale + tradeoffs for what was prioritized** — [`CREATIVITY.md`](CREATIVITY.md) (incl. 4 honest future extensions).

## Submission
- [x] **Repo links + live URLs collected** — [`SUBMISSION.md`](SUBMISSION.md).
- [x] **Final read-through against this checklist** — this document.

---
**Net state: all items green.** The only caveat worth the panel's attention is the CV instance itself —
no native events/baselines/groups — which we turned into a deliberate design decision (authored policy)
rather than a gap, and documented in full.
