"""
Run all three alert detectors over the saved CV samples (default) or live data (--live),
and print a summary table. This is the Phase-2 review harness — no FastAPI, no UI.

    .venv/Scripts/python scripts/run_alerts_offline.py
    .venv/Scripts/python scripts/run_alerts_offline.py --live
    .venv/Scripts/python scripts/run_alerts_offline.py --silence-seconds 90 --vuln-min-score 80
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

# Windows consoles default to cp1252 and choke on the arrows we use in titles.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:  # noqa: BLE001
    pass

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.alerts.custom import communicating_keys, detect_vulnerable_exposure  # noqa: E402
from app.alerts.operations import detect_silent_assets  # noqa: E402
from app.alerts.security import detect_cross_zone_violations  # noqa: E402
from app.models import Activity, Alert, Asset, Policy, Vulnerability  # noqa: E402

SAMPLES = Path(__file__).resolve().parents[1] / "docs" / "api-samples"


def _read(name: str):
    return json.loads((SAMPLES / name).read_text(encoding="utf-8"))


def _sample_list(name: str) -> list:
    """Trimmed committed samples are wrapped as {sample: [...]}; raw dumps are bare lists."""
    obj = _read(name)
    if isinstance(obj, list):
        return obj
    return obj.get("sample", [])


def load_dataset(live: bool) -> tuple[list[dict], list[dict], dict[str, list]]:
    if live:
        import warnings

        warnings.simplefilter("ignore")
        from app.cv_client import CVClient

        with CVClient() as cv:
            comps = cv.get_components()
            acts = cv.get_activities()
            vuln_map = {
                c["id"]: cv.get_component_vulnerabilities(c["id"])
                for c in comps
                if c.get("vulnerabilitiesCount", 0) > 0
            }
        return comps, acts, vuln_map

    # offline: prefer full raw dumps, fall back to trimmed committed samples
    comps = _read("components.raw.json") if (SAMPLES / "components.raw.json").exists() else _sample_list("components.json")
    if (SAMPLES / "activities.raw.json").exists():
        acts = _read("activities.raw.json")
    else:
        acts = _sample_list("activities_alldata.json")
    vuln_map = _read("component_vulns.raw.json") if (SAMPLES / "component_vulns.raw.json").exists() else {}
    return comps, acts, vuln_map


def run(args) -> dict[str, list[Alert]]:
    policy = Policy.load()
    levels = policy.purdue_levels
    ctags = tuple(policy.controller_tags)

    comps, acts, vuln_map = load_dataset(args.live)

    assets = [Asset.from_component(c, levels, ctags) for c in comps]
    activities = [Activity.from_raw(a, levels, ctags) for a in acts]
    by_id = {c["id"]: c for c in comps}
    assets_with_vulns = [
        (Asset.from_component(by_id[cid], levels, ctags), [Vulnerability.from_raw(v) for v in vlist])
        for cid, vlist in vuln_map.items()
        if cid in by_id
    ]

    comm_ips, comm_macs = communicating_keys(activities)
    ref = max((a.last_seen_ms for a in activities if a.last_seen_ms), default=None)

    return {
        "operations": detect_silent_assets(assets, min_seconds_behind_zone_median=args.silence_seconds),
        "security": detect_cross_zone_violations(activities, policy),
        "custom": detect_vulnerable_exposure(
            assets_with_vulns, comm_ips, comm_macs, min_score=args.vuln_min_score,
            detected_at=__import__("app.alerts._util", fromlist=["ms_to_iso"]).ms_to_iso(ref),
        ),
    }, len(assets), len(activities), len(assets_with_vulns)


def print_summary(results: dict[str, list[Alert]], n_assets: int, n_acts: int, n_vuln: int) -> None:
    print(f"\nDataset: {n_assets} assets | {n_acts} activities | {n_vuln} assets-with-CVEs\n")
    print(f"{'ALERT':<14}{'CATEGORY':<12}{'FIRED':>6}   SEVERITY BREAKDOWN")
    print("-" * 72)
    for key in ("operations", "security", "custom"):
        alerts = results[key]
        sev = Counter(a.severity.value for a in alerts)
        sev_str = ", ".join(f"{k}={sev[k]}" for k in ("critical", "high", "medium", "low") if sev.get(k))
        cat = alerts[0].category.value if alerts else key
        print(f"{key:<14}{cat:<12}{len(alerts):>6}   {sev_str or '-'}")
    print("-" * 72)

    for key in ("operations", "security", "custom"):
        alerts = results[key]
        print(f"\n### {key.upper()} — top {min(3, len(alerts))} of {len(alerts)}")
        for a in alerts[:3]:
            if key == "operations":
                label = f"{a.assets[0].name} [{a.assets[0].mac}]"
                extra = f"  ({a.evidence['seconds_behind_zone_median']}s behind {a.evidence['subnet']})"
            elif key == "security":
                label = a.title
                extra = f"  [{a.evidence['rule']}]"
            else:  # custom
                label = a.assets[0].name
                extra = f"  score={a.score} cves={a.evidence['cve_count']} maxCVSS={a.evidence['max_cvss']}"
            print(f"  [{a.severity.value:>8}] {label}{extra}")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--live", action="store_true", help="pull fresh data from the Center")
    p.add_argument("--silence-seconds", type=float, default=60.0)
    p.add_argument("--vuln-min-score", type=float, default=80.0)
    p.add_argument("--json", action="store_true", help="dump full alerts as JSON")
    args = p.parse_args()

    (results, na, nac, nv) = run(args)
    if args.json:
        print(json.dumps({k: [a.model_dump() for a in v] for k, v in results.items()}, indent=2, default=str))
        return
    print_summary(results, na, nac, nv)


if __name__ == "__main__":
    main()
