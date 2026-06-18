"""
Data service: the single place that turns CV data into a computed "bundle"
(inventory + comms graph + the three alert sets). Endpoints read the bundle; they never
touch CV or the detectors directly.

Resilience: try the live Center first; on ANY failure fall back to the saved samples in
docs/api-samples/ so the demo never hard-fails. Every bundle records data_source = "live" |
"snapshot". Cold-start safe: nothing is fetched until the first request builds the bundle.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from app import config
from app.alerts._util import ms_to_iso
from app.alerts.custom import communicating_keys, cross_zone_keys, detect_vulnerable_exposure
from app.alerts.operations import detect_silent_assets
from app.alerts.security import detect_cross_zone_violations
from app.cache import TTLCache
from app.models import Activity, Alert, Asset, Policy, Vulnerability

SAMPLES = Path(__file__).resolve().parents[1] / "docs" / "api-samples"

RawTriple = tuple[list[dict], list[dict], dict[str, list]]


# --- raw loaders (monkeypatchable seams for tests) ---------------------------
def _fetch_live() -> RawTriple:
    from app.cv_client import CVClient  # imported lazily so snapshot-only runs need no creds

    with CVClient() as cv:
        comps = cv.get_components()
        acts = cv.get_activities()
        vuln_map = {
            c["id"]: cv.get_component_vulnerabilities(c["id"])
            for c in comps
            if c.get("vulnerabilitiesCount", 0) > 0
        }
    if not comps:
        raise RuntimeError("live fetch returned no components")
    return comps, acts, vuln_map


def _sample_list(name: str) -> list:
    obj = json.loads((SAMPLES / name).read_text(encoding="utf-8"))
    return obj if isinstance(obj, list) else obj.get("sample", [])


def _first_existing(*names: str) -> str | None:
    for n in names:
        if (SAMPLES / n).exists():
            return n
    return None


def _load_snapshot() -> RawTriple:
    """Load the bundled snapshot. Preference order:
       1. *.snapshot.json  — the full committed dataset that ships to the deployed demo,
       2. *.raw.json       — full local dumps (dev, gitignored),
       3. trimmed *.json    — the tiny committed test fixtures (last resort)."""
    comps = _sample_list(_first_existing("components.snapshot.json", "components.raw.json", "components.json") or "components.json")
    acts = _sample_list(_first_existing("activities.snapshot.json", "activities.raw.json", "activities_alldata.json") or "activities_alldata.json")
    vm_name = _first_existing("component_vulns.snapshot.json", "component_vulns.raw.json")
    vuln_map = json.loads((SAMPLES / vm_name).read_text(encoding="utf-8")) if vm_name else {}
    return comps, acts, vuln_map


def _load_raw() -> tuple[RawTriple, str]:
    # DATA_MODE=snapshot (default, and what the public Render demo runs): NEVER touch the Center.
    if config.data_mode() == "snapshot" or os.getenv("CV_FORCE_SNAPSHOT") == "1":
        return _load_snapshot(), "snapshot"
    # DATA_MODE=live (local dev with a token): call the Center, fall back to snapshot on any failure.
    try:
        return _fetch_live(), "live"
    except Exception:  # noqa: BLE001 — any transport/auth/empty error -> graceful fallback
        return _load_snapshot(), "snapshot"


# --- computed bundle ---------------------------------------------------------
@dataclass
class Bundle:
    data_source: str
    reference_now_ms: int | None
    reference_now_iso: str | None
    assets: list[Asset]
    activities: list[Activity]
    cve_count: dict[str, int]
    max_cvss: dict[str, float]
    alerts: dict[str, list[Alert]] = field(default_factory=dict)

    @property
    def all_alerts(self) -> list[Alert]:
        return [a for group in self.alerts.values() for a in group]


def build_bundle() -> Bundle:
    policy = Policy.load()
    levels = policy.purdue_levels
    ctags = tuple(policy.controller_tags)

    (comps, acts, vuln_map), source = _load_raw()

    assets = [Asset.from_component(c, levels, ctags) for c in comps]
    activities = [Activity.from_raw(a, levels, ctags) for a in acts]
    by_id = {c["id"]: c for c in comps}

    parsed_vulns: dict[str, list[Vulnerability]] = {
        cid: [Vulnerability.from_raw(v) for v in vlist] for cid, vlist in vuln_map.items()
    }
    assets_with_vulns = [(Asset.from_component(by_id[cid], levels, ctags), vl)
                         for cid, vl in parsed_vulns.items() if cid in by_id]
    max_cvss = {cid: max((v.cvss for v in vl), default=0.0) for cid, vl in parsed_vulns.items()}
    cve_count = {cid: len(vl) for cid, vl in parsed_vulns.items()}

    comm_ips, comm_macs = communicating_keys(activities)
    cz_ips, cz_macs = cross_zone_keys(activities)
    ref_ms = max((a.last_seen_ms for a in activities if a.last_seen_ms),
                 default=max((a.last_seen_ms for a in assets if a.last_seen_ms), default=None))
    ref_iso = ms_to_iso(ref_ms)

    alerts = {
        "operations": detect_silent_assets(assets, reference_now_ms=ref_ms),
        "security": detect_cross_zone_violations(activities, policy),
        "custom": detect_vulnerable_exposure(
            assets_with_vulns, comm_ips, comm_macs,
            cross_zone_ips=cz_ips, cross_zone_macs=cz_macs, detected_at=ref_iso,
        ),
    }
    return Bundle(
        data_source=source,
        reference_now_ms=ref_ms,
        reference_now_iso=ref_iso,
        assets=assets,
        activities=activities,
        cve_count=cve_count,
        max_cvss=max_cvss,
        alerts=alerts,
    )


_cache: TTLCache[Bundle] = TTLCache(config.cache_ttl_seconds())


def get_bundle(*, force: bool = False) -> Bundle:
    return _cache.get(build_bundle, force=force)
