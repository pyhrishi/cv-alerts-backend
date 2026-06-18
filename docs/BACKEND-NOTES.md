# Backend — cv-alerts-backend (FastAPI on Render)

Secure proxy + alert engine in front of the Cyber Vision API. See root CLAUDE.md for the
big picture and `.claude/skills/` for how to talk to CV, design alerts, and deploy.

## Responsibilities
- Own ALL Cyber Vision API access (one client module). The token stays here, server-side.
- Normalize raw CV data into typed Pydantic models.
- Compute the three alerts (security / operations / free-choice) over cached data.
- Expose clean REST: `/healthz`, `/assets`, `/alerts`, `/graph`, `/kpis`.

## Suggested layout
```
app/
  main.py            # FastAPI app, CORS, routes
  config.py          # env loading (CV_BASE_URL, CV_API_TOKEN, ALLOWED_ORIGINS)
  cv_client.py       # the ONLY place that calls Cyber Vision (httpx, verify=False here)
  cache.py           # TTL cache
  models.py          # Pydantic: Asset, Flow, Alert, Kpi, GraphNode/Edge
  alerts/
    operations.py    # "device went silent"
    security.py      # "unexpected/unauthorized asset"
    custom.py        # chosen free-choice alert
  graph.py           # build comms graph from flows
tests/
  test_operations.py test_security.py test_custom.py   # fixtures from real CV samples
render.yaml
requirements.txt
.env.example
```

## Rules
- `verify=False` lives ONLY in cv_client.py with an "exercise-only" comment.
- Never log/return the token. Tight CORS (no `*` in submission).
- Each alert detection function is pure + unit tested with captured-sample fixtures.
