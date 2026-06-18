"""
Dump FULL real datasets from the Center to docs/api-samples/*.raw.json for local tuning.

These *.raw.json files are gitignored (large, instance-specific). The trimmed, committed
*.json samples remain the test fixtures. Run this once to refresh local data:

    .venv/Scripts/python scripts/fetch_samples.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # import app.*
from app.cv_client import CVClient  # noqa: E402

SAMPLES = Path(__file__).resolve().parents[1] / "docs" / "api-samples"


def main() -> None:
    SAMPLES.mkdir(parents=True, exist_ok=True)
    with CVClient() as cv:
        comps = cv.get_components()
        (SAMPLES / "components.raw.json").write_text(json.dumps(comps, indent=2), encoding="utf-8")
        print(f"components.raw.json         : {len(comps)} assets")

        acts = cv.get_activities()
        (SAMPLES / "activities.raw.json").write_text(json.dumps(acts, indent=2), encoding="utf-8")
        print(f"activities.raw.json         : {len(acts)} links")

        # per-asset CVEs only for components that actually carry vulnerabilities
        vuln_map: dict[str, list] = {}
        with_vuln = [c for c in comps if c.get("vulnerabilitiesCount", 0) > 0]
        for i, c in enumerate(with_vuln, 1):
            try:
                vuln_map[c["id"]] = cv.get_component_vulnerabilities(c["id"])
            except Exception as e:  # noqa: BLE001
                print(f"  warn: {c.get('label')} vulns failed: {type(e).__name__}")
            if i % 10 == 0:
                print(f"  ...fetched vulns for {i}/{len(with_vuln)} assets")
        (SAMPLES / "component_vulns.raw.json").write_text(json.dumps(vuln_map, indent=2), encoding="utf-8")
        print(f"component_vulns.raw.json    : {len(vuln_map)} assets with CVEs")


if __name__ == "__main__":
    import warnings

    warnings.simplefilter("ignore")  # silence the verify=False warning for this CLI
    main()
