"""
Phase 1 (part 2) — ground the exact endpoint surface from the live OpenAPI spec,
and resolve the two gaps from discover.py: flows=0 (likely preset-scoped) and events=404.

READ-ONLY. Never prints the token.
"""
from __future__ import annotations
import json, sys
from pathlib import Path
import httpx
from dotenv import dotenv_values

BACKEND_DIR = Path(__file__).resolve().parents[1]
SAMPLES_DIR = BACKEND_DIR.parent / "docs" / "api-samples"
_env = dotenv_values(BACKEND_DIR / ".env")
BASE = (_env.get("CV_BASE_URL") or "").rstrip("/")
TOKEN = _env.get("CV_API_TOKEN") or ""
HEADER = "x-token-id"
V = "/api/3.0"

client = httpx.Client(
    base_url=BASE,
    headers={HEADER: TOKEN, "Accept": "application/json"},
    verify=False,  # exercise-only: self-signed cert
    timeout=30.0,
)

def get(path, **params):
    try:
        r = client.get(path, params=params or None)
    except httpx.HTTPError as e:
        return None, f"<{type(e).__name__}>"
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, r.text[:200]

# --- 1. Try to pull the OpenAPI / swagger spec so we have the real path list ---
print("=== OpenAPI spec hunt ===")
spec = None
for cand in ["/api/3.0/openapi.json", "/api/3.0/swagger.json", "/api/3.0/api-docs",
             "/api/3.0/doc.json", "/openapi.json", "/swagger.json", "/api-docs",
             "/api/3.0/spec", "/api/3.0/swagger"]:
    s, b = get(cand)
    print(f"  {cand:<28} -> {s}")
    if s and 200 <= s < 300 and isinstance(b, dict) and ("paths" in b or "swagger" in b or "openapi" in b):
        spec = b
        (SAMPLES_DIR / "_openapi.json").write_text(json.dumps(b, indent=2), encoding="utf-8")
        print(f"  >>> captured spec at {cand}")
        break

if spec and "paths" in spec:
    paths = sorted(spec["paths"].keys())
    print(f"\n=== {len(paths)} paths in spec ===")
    for p in paths:
        methods = ",".join(m.upper() for m in spec["paths"][p].keys())
        print(f"  {methods:<12} {p}")
    (SAMPLES_DIR / "_openapi_paths.txt").write_text(
        "\n".join(f"{','.join(m.upper() for m in spec['paths'][p])}  {p}" for p in paths),
        encoding="utf-8")

# --- 2. Counts via the X-Total-Count header (CV returns it on list endpoints) ---
print("\n=== total counts (X-Total-Count header) ===")
for ep in ["/components", "/vulnerabilities", "/flows", "/activities", "/sensors", "/tags", "/groups"]:
    try:
        r = client.get(f"{V}{ep}", params={"page": 1, "size": 1})
        total = r.headers.get("X-Total-Count") or r.headers.get("x-total-count")
        print(f"  {ep:<18} status={r.status_code}  X-Total-Count={total}")
    except httpx.HTTPError as e:
        print(f"  {ep:<18} <{type(e).__name__}>")

# --- 3. Resolve flows / activities: try preset-scoped routes ---
print("\n=== preset-scoped flow/activity probing ===")
s, presets = get(f"{V}/presets")
preset_ids = []
if isinstance(presets, list):
    # prefer a preset whose label hints at 'all data', else take the first few
    presets_sorted = sorted(presets, key=lambda p: (("all" not in (p.get("label","").lower())), p.get("label","")))
    preset_ids = [(p["id"], p.get("label","")) for p in presets_sorted[:3]]
    print("  candidate presets:", [(pid[:8], lbl) for pid, lbl in preset_ids])

# candidate templates relative to a preset id
PRESET_TEMPLATES = [
    "/presets/{pid}/visualisations/activity-list",
    "/presets/{pid}/visualisations/component-list",
    "/presets/{pid}/visualisations/node-link",
    "/presets/{pid}/activities",
    "/presets/{pid}/flows",
    "/presets/{pid}/components",
    "/presets/{pid}/data/activities",
]
# also try global activities/flows with a preset query param
GLOBAL_WITH_PRESET = ["/activities", "/flows"]

best_activity_sample = None
for pid, lbl in preset_ids:
    print(f"  -- preset {pid[:8]} ({lbl}) --")
    for tmpl in PRESET_TEMPLATES:
        path = V + tmpl.format(pid=pid)
        s, b = get(path, page=1, size=5)
        n = len(b) if isinstance(b, list) else (len(b.get("activities", b.get("components", []))) if isinstance(b, dict) else "?")
        if s and 200 <= s < 300:
            print(f"     [OK ] {tmpl:<45} -> {s}  n={n}")
            if "activity" in tmpl and isinstance(b, (list, dict)) and best_activity_sample is None and n not in (0, "?"):
                best_activity_sample = (path, b)
        elif s != 404:
            print(f"     [{s}] {tmpl}")
    for ep in GLOBAL_WITH_PRESET:
        s, b = get(f"{V}{ep}", preset=pid, page=1, size=5)
        n = len(b) if isinstance(b, list) else "?"
        if s and 200 <= s < 300 and n not in (0, "?"):
            print(f"     [OK ] {ep}?preset= -> {s}  n={n}")

if best_activity_sample:
    path, b = best_activity_sample
    trimmed = b[:3] if isinstance(b, list) else b
    (SAMPLES_DIR / "activities.json").write_text(
        json.dumps({"_endpoint": path, "sample": trimmed}, indent=2), encoding="utf-8")
    print(f"\n  >>> saved activity sample from {path}")

# --- 4. events alternatives ---
print("\n=== events alternatives ===")
for ep in ["/events", "/event", "/security/events", "/reports", "/baselines", "/alerts",
           "/monitor/events", "/diff", "/baselines/events"]:
    s, b = get(f"{V}{ep}", page=1, size=2)
    if s != 404:
        print(f"  {ep:<22} -> {s}")

client.close()
print("\nDONE")
