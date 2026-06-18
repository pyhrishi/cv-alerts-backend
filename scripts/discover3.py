"""
Phase 1 (part 3) — true counts, baselines (security-alert source), and CVE->component linkage.
READ-ONLY. Never prints the token.
"""
from __future__ import annotations
import json
from pathlib import Path
import httpx
from dotenv import dotenv_values

BACKEND_DIR = Path(__file__).resolve().parents[1]
SAMPLES_DIR = BACKEND_DIR.parent / "docs" / "api-samples"
_env = dotenv_values(BACKEND_DIR / ".env")
BASE = (_env.get("CV_BASE_URL") or "").rstrip("/")
TOKEN = _env.get("CV_API_TOKEN") or ""
V = "/api/3.0"
client = httpx.Client(base_url=BASE, headers={"x-token-id": TOKEN, "Accept": "application/json"},
                      verify=False, timeout=60.0)  # verify=False: exercise-only self-signed cert

def get(path, **p):
    try:
        r = client.get(path, params=p or None)
    except httpx.HTTPError as e:
        return None, f"<{type(e).__name__}>"
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, r.text[:200]

ALL_DATA = "d5af074a"  # 'All data' preset prefix; resolve full id below
s, presets = get(f"{V}/presets")
all_data_id = next((p["id"] for p in presets if p.get("label") == "All data"), None)
all_ctrl_id = next((p["id"] for p in presets if p.get("label") == "All Controllers"), None)
print(f"All data preset id: {all_data_id}")
print(f"All Controllers preset id: {all_ctrl_id}")

print("\n=== true counts (request big size, count array) ===")
for name, path in [("components", f"{V}/components"), ("vulnerabilities", f"{V}/vulnerabilities"),
                   ("sensors", f"{V}/sensors"), ("tags", f"{V}/tags"),
                   ("activities(global)", f"{V}/activities"),
                   ("flows(global)", f"{V}/flows")]:
    s, b = get(path, size=100000, page=1)
    n = len(b) if isinstance(b, list) else "n/a"
    print(f"  {name:<20} status={s}  count={n}")

# components within the 'All data' preset (the real inventory for the dashboard)
if all_data_id:
    s, b = get(f"{V}/presets/{all_data_id}/visualisations/component-list", size=100000, page=1)
    print(f"  components(All data preset) status={s} count={len(b) if isinstance(b,list) else 'n/a'}")
    s, b = get(f"{V}/presets/{all_data_id}/visualisations/activity-list", size=100000, page=1)
    n = len(b) if isinstance(b, list) else 'n/a'
    print(f"  activities(All data preset) status={s} count={n}")
    if isinstance(b, list) and b:
        (SAMPLES_DIR / "activities_alldata.json").write_text(
            json.dumps({"_endpoint": f"{V}/presets/{all_data_id}/visualisations/activity-list",
                        "_count": n, "sample": b[:3]}, indent=2), encoding="utf-8")

print("\n=== baselines (candidate security-alert source) ===")
s, baselines = get(f"{V}/baselines")
print(f"  /baselines status={s}  type={type(baselines).__name__}  "
      f"count={len(baselines) if isinstance(baselines, list) else 'n/a'}")
if isinstance(baselines, list) and baselines:
    (SAMPLES_DIR / "baselines.json").write_text(
        json.dumps({"_endpoint": f"{V}/baselines", "_count": len(baselines),
                    "sample": baselines[:3]}, indent=2), encoding="utf-8")
    bid = baselines[0].get("id")
    print(f"  first baseline id={str(bid)[:8]} keys={list(baselines[0].keys())}")
    for sub in [f"/baselines/{bid}", f"/baselines/{bid}/events", f"/baselines/{bid}/activities",
                f"/baselines/{bid}/diff", f"/baselines/{bid}/components"]:
        s2, _ = get(f"{V}{sub}")
        print(f"    {sub.replace(str(bid), str(bid)[:8]):<40} -> {s2}")

print("\n=== CVE -> component linkage ===")
s, comps = get(f"{V}/components", size=100000)
withvuln = [c for c in comps if isinstance(c, dict) and c.get("vulnerabilitiesCount", 0) > 0] if isinstance(comps, list) else []
print(f"  components with vulnerabilitiesCount>0: {len(withvuln)}")
if withvuln:
    cid = withvuln[0]["id"]
    print(f"  probing component {cid[:8]} (vulnCount={withvuln[0]['vulnerabilitiesCount']})")
    for sub in [f"/components/{cid}", f"/components/{cid}/vulnerabilities", f"/components/{cid}/activities"]:
        s2, b2 = get(f"{V}{sub}")
        n = len(b2) if isinstance(b2, list) else "?"
        print(f"    {sub.replace(cid, cid[:8]):<42} -> {s2}  n={n}")
        if sub.endswith("/vulnerabilities") and s2 and 200 <= s2 < 300:
            (SAMPLES_DIR / "component_vulnerabilities.json").write_text(
                json.dumps({"_endpoint": f"{V}{sub}", "sample": b2[:3] if isinstance(b2, list) else b2},
                           indent=2), encoding="utf-8")

# save a sensors sample for context (network capture points)
s, sensors = get(f"{V}/sensors")
if isinstance(sensors, list) and sensors:
    (SAMPLES_DIR / "sensors.json").write_text(
        json.dumps({"_endpoint": f"{V}/sensors", "_count": len(sensors), "sample": sensors[:3]}, indent=2),
        encoding="utf-8")

client.close()
print("\nDONE")
