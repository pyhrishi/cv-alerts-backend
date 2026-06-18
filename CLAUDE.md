# Project Memory — Cisco Cyber Vision Alert Framework

## What this is
An interview deliverable for a **Cisco Technical Product Manager (AI Builder)** role.
We are building a **standalone, interactive alerts dashboard** for **Cisco Cyber Vision**
(an OT/ICS network monitoring product), backed by **live data pulled programmatically**
from a provided Cyber Vision Center API.

You (Claude Code) are the implementation engineer. A human PM ("the user") relays
prioritized, step-by-step prompts. Do exactly the scoped step, report results, and stop —
do not race ahead and build later phases before the current one is confirmed.

## The graded objective (do not lose sight of this)
1. Connect to the CV Center **programmatically via API key** (not scraping).
2. Build a standalone dashboard with an **Alerts page showing THREE new alerts**:
   - one **Security** alert
   - one **Operations** alert
   - one **free-choice** alert
   Each alert MUST be grounded in data that actually exists in this CV instance.
3. **Visualize communication relations** between assets (a network/topology graph).
4. Ship: git repos, dashboard, tabular + visual reports, and a written explanation of
   design choices + intended audience + setup/testing instructions.

This is a PM role, so HOW we decide matters as much as WHAT we build: document
assumptions, tradeoffs, prioritization, and limitations transparently.

## Architecture (locked)
Two repos, deployed separately:

- `cv-alerts-backend/`  → FastAPI (Python) + httpx + Pydantic → **Render**
  - Acts as a secure proxy + alert engine in front of the CV API.
  - **The CV API key lives ONLY here, server-side.** Never expose it to the browser.
  - Normalizes raw CV data into clean typed models; computes the three alerts.
  - Caches CV responses (TTL) to avoid hammering a slow/rate-limited center.
- `cv-alerts-frontend/` → Next.js + TypeScript + Tailwind → **Vercel**
  - Dashboard UI: Alerts page + communication-relations graph (Cytoscape.js) + KPI charts (Recharts).
  - Talks ONLY to our backend, never to the CV center directly.

## Non-negotiable rules
- **Secrets**: real credentials live in local `.env` (gitignored) and in Render/Vercel
  dashboard env vars. NEVER commit the API key, password, or center URL into git.
  `.env.example` files list variable NAMES only, with placeholder values.
- **Self-signed TLS**: the CV center is served over HTTPS on a raw IP with a self-signed
  cert. Backend httpx calls use `verify=False` for this exercise — but isolate that in one
  place and add a code comment flagging it as exercise-only, not production-safe.
- **Confirm before building**: Phase 1 (API discovery) MUST succeed and be reviewed by
  the PM before we design alerts. Do not invent endpoints or data shapes — discover them.
- **Maintainable code**: small modules, typed, with a test for each alert's detection logic.
- **Document as you go**: keep `docs/ARCHITECTURE.md` and `docs/DELIVERABLES-CHECKLIST.md` current.

## Where to look
- `docs/ASSIGNMENT.md` — the full assignment digest.
- `docs/DELIVERABLES-CHECKLIST.md` — every required item; keep it ticking green.
- `.claude/skills/` — how to talk to the CV API, how to design alerts, UI conventions, deploy steps.
- `.claude/agents/` — specialist subagents (api-explorer, alert-engineer, frontend-builder, doc-writer).

## Definition of done (per the PDF)
Technical quality, problem-solving/prioritization, communication, engineering practices
(tests, structure, version control), product thinking, and creativity. A submission that
runs cleanly from a fresh clone with documented setup beats a fancier one that doesn't.
