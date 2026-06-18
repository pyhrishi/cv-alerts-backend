# Skill: Cyber Vision API Client

## When to use
Any time you connect to, query, or model data from the Cyber Vision Center API.

## Connection facts
- Base URL comes from env var `CV_BASE_URL` (e.g. `https://<center-ip>`). Never hardcode.
- API key comes from env var `CV_API_TOKEN`. Never hardcode, never log, never return to client.
- The center uses a **self-signed certificate**. Set TLS verification OFF for this exercise only:
  - httpx: `httpx.AsyncClient(verify=False)`  (wrap once; comment "exercise-only")
  - curl:  `-k`
- The CV API is **versioned** (commonly under `/api/3.0/...`). DO NOT assume the version or
  endpoint names — CONFIRM them against the live docs first (see below).

## Authoritative source of truth — read this FIRST
The live, instance-specific API documentation is at:
  `${CV_BASE_URL}/#/admin/api/documentation`
There is also a public reference: https://developer.cisco.com/docs/cyber-vision/getting-started/
Cyber Vision typically authenticates with the header **`x-token-id: <token>`** — but VERIFY
the exact header name and the route version from the live docs before building the client.
If `x-token-id` returns 401/403, try the alternatives the docs list, and record what works.

## Discovery procedure (Phase 1)
1. Smoke test reachability + auth with a single curl against the most basic endpoint
   (e.g. version/ping/presets). Capture HTTP status + a snippet of the body.
2. Enumerate the endpoints that matter for alerts and a comms graph:
   - **components / devices / assets** — the inventory (what's on the network)
   - **flows / activities / conversations** — who talks to whom (the comms graph + silence detection)
   - **vulnerabilities** — CVEs per component (candidate free-choice alert)
   - **events** — system/security events already raised by CV
   - **presets / groups** — logical groupings (zones), useful for Purdue-model logic
3. For each working endpoint, save a trimmed real sample to `docs/api-samples/<endpoint>.json`
   (redact nothing sensitive that isn't a secret; do NOT save the token).
4. Note pagination style (page/size, cursor, offset/limit), rate-limit behavior, and any field
   that carries a timestamp (critical for "device went silent" detection).

## Output of this skill
A `docs/API-FINDINGS.md` written in plain language for the PM: which endpoints exist, what
each returns, which fields we can build alerts on, and any gaps/limitations.

## Hard rules
- One client module owns all CV access; the rest of the app calls that module, not the center.
- Cache responses (TTL) — never poll the center on every browser request.
- Never put the token in a URL, log line, error message, or client response.
