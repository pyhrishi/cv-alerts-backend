# Skill: Deployment (Render + Vercel)

## When to use
Wiring up hosting, environment variables, CORS, or writing setup/run docs.

## Backend → Render (`cv-alerts-backend`)
- Service type: Web Service (Python). Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`.
- Render injects `$PORT` — read it, don't hardcode.
- Env vars set in the Render dashboard (NOT in git): `CV_BASE_URL`, `CV_API_TOKEN`, plus
  `ALLOWED_ORIGINS` (the Vercel URL).
- Add a `render.yaml` (infra-as-code) so the service is reproducible.
- Health check endpoint `GET /healthz` returning `{status:"ok"}`.

## Frontend → Vercel (`cv-alerts-frontend`)
- Next.js auto-detected. Env var `NEXT_PUBLIC_API_BASE_URL` = the Render backend URL.
- Set env vars in Vercel project settings (NOT in git).

## CORS
Backend must allow the Vercel origin via `ALLOWED_ORIGINS`. Keep it tight (no `*` in the
submitted version) and document why — it's a security product, model good practice.

## Local dev parity
- `docker-compose` optional; at minimum a documented two-terminal flow:
  backend `uvicorn` on :8000, frontend `next dev` on :3000 pointing at it.
- Each repo's README has copy-paste setup, run, and test commands that work from a fresh clone.

## Free-tier reality
Render free web services sleep on idle (cold starts ~30–60s). Note this in docs and add a
graceful "backend waking up" loading state in the UI so a reviewer's first hit doesn't look broken.
