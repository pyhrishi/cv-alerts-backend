# Architecture & Design Notes

## System shape
Browser (Vercel/Next.js) → our Backend (Render/FastAPI) → Cyber Vision Center API.
The frontend never contacts the CV center directly.

## Why a backend proxy (key decision)
1. **Secret isolation** — the CV API token stays server-side; the browser never sees it.
   For a security product this is the difference between a credible and a disqualifying submission.
2. **Normalization** — raw CV payloads are reshaped into clean, typed alert/asset models.
3. **Alert engine** — detection logic runs server-side over cached data, not in the client.
4. **Resilience** — TTL caching shields a slow/rate-limited OT center from per-request load.

## Data flow
Backend polls/queries CV → caches → computes alerts → exposes clean REST endpoints
(`/alerts`, `/assets`, `/graph`, `/kpis`, `/healthz`). Frontend polls these on an interval.

## Alert model
See `.claude/skills/alert-design/SKILL.md` for the Alert contract. Severity is rule-derived
and documented; evidence is captured for auditability.

## Tradeoffs (running log — append as decisions are made)
- Poll-based snapshots, not streaming (matches exercise scope; real-time noted as future work).
- verify=False for the self-signed CV cert (exercise-only; flagged in code).
- Render free tier cold starts (mitigated with a "waking up" UI state).
- (add more as we go)

## Known limitations (running log)
- (fill in transparently as discovered)
