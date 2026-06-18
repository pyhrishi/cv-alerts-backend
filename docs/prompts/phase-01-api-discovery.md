# PHASE 1 PROMPT — Bootstrap workspace + Cyber Vision API discovery
# (Paste this into Claude Code. Do ONLY this phase, then report back.)

You are working in this VSCode workspace. Read `CLAUDE.md`, `docs/ASSIGNMENT.md`, and
`.claude/skills/cv-api-client/SKILL.md` before doing anything.

GOAL OF THIS PHASE: prove we can reach the Cyber Vision Center programmatically and map out
exactly what data is available. Do NOT build the dashboard, alerts, or any UI yet.

Steps:
1. In `cv-alerts-backend/`, create a local `.env` from `.env.example` and fill in the real
   CV_BASE_URL and CV_API_TOKEN from my assignment PDF (I will paste them to you / they are
   already in the env). Confirm `.env` is gitignored.
2. Set up a minimal Python env in `cv-alerts-backend/` (requirements: httpx, python-dotenv).
   Do NOT scaffold the full FastAPI app yet — just enough to run a discovery script.
3. Write `cv-alerts-backend/scripts/discover.py` that:
   - loads CV_BASE_URL and CV_API_TOKEN from .env (never prints the token),
   - uses httpx with verify=False (self-signed cert; comment it as exercise-only),
   - confirms auth against a basic endpoint and prints ONLY the HTTP status,
   - then probes: components/devices/assets, flows/activities, vulnerabilities, events,
     presets/groups. First CONFIRM the correct API version path and auth header against the
     live docs at ${CV_BASE_URL}/#/admin/api/documentation (the header is likely `x-token-id`
     but verify). Try alternatives if the first attempt 401/403s.
   - saves a trimmed real sample of each working endpoint to `docs/api-samples/<name>.json`.
4. Write `docs/API-FINDINGS.md` in plain language for me (the PM): for each endpoint — does it
   work, what does it return, which fields carry timestamps, IPs/MACs, asset identity, zones,
   CVEs, and flow source/destination. Then state, for each of the three planned alerts
   (operations "device silent", security "unexpected asset", and free-choice candidates),
   whether the data needed actually exists here.
5. Initialize git in `cv-alerts-backend/` and `cv-alerts-frontend/` as two separate repos with
   an initial commit (scaffold + this discovery work for backend). Do NOT commit any secrets —
   verify `git status` shows no `.env`.

REPORT BACK to me with:
- Did auth work? Which header + API version path?
- The list of working endpoints and a one-line description of each.
- Your honest read on which three alerts are best supported by the real data.
- Anything broken, empty, or surprising.

Then STOP. We design alerts together based on what you actually found.
