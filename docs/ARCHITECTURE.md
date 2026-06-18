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

## DATA_MODE: snapshot vs live (public-demo safety — key decision)
The backend has two modes, controlled by the `DATA_MODE` env var:

- **`snapshot` (default, and what the public Render demo runs).** Every endpoint serves a
  **frozen, bundled copy** of the dataset (`docs/api-samples/*.snapshot.json`) and the service
  **never opens a connection to the Cyber Vision Center**. No token is required or present.
- **`live` (local dev / a private deployment).** The backend calls the Center (requires
  `CV_BASE_URL` + `CV_API_TOKEN`) and falls back to snapshot if the Center is unreachable.

**Why default to snapshot on the public URL:**
1. **Don't publish live OT telemetry.** Continuously exposing a real industrial network's live
   asset/flow/vulnerability data on a public endpoint is exactly the kind of leak an OT security
   product should not create. A frozen snapshot of the Cisco-provided interview sandbox is enough
   to demonstrate the product without standing up a live data tap to the open internet.
2. **No secret on a public host.** Snapshot mode needs no API token, so there is nothing
   sensitive to leak from the public service even in principle.
3. **No load on the Center.** A public URL can be hit by anyone (and by crawlers); we must not
   relay that traffic onto a slow, rate-limited OT center.
4. **Reliability for reviewers.** The demo can't break because the Center is asleep or the token
   rotated.

The `data_source` field in every response (and the badge on the dashboard) **always reflects
reality** — `"snapshot"` on the public demo, `"live"` (or `"snapshot"` after a fallback) in live
mode — so the honesty-on-the-glass promise holds. The bundled snapshot contains no credentials.

## Tradeoffs (running log — append as decisions are made)
- Public demo runs DATA_MODE=snapshot (frozen sample data) — see rationale above.
- Poll-based snapshots, not streaming (matches exercise scope; real-time noted as future work).
- verify=False for the self-signed CV cert (exercise-only; flagged in code).
- Render free tier cold starts (mitigated with a "waking up" UI state).
- (add more as we go)

## Known limitations (running log)
- (fill in transparently as discovered)
