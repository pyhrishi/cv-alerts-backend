"""
FREE-CHOICE alert — "Vulnerable asset exposure".

Why this one: the per-component CVE data is the richest, best-grounded dataset on this Center
(45/180 assets carry CVEs, real CVSS up to 10.0). A raw "has a CVE" alert is useless here —
ALL 45 vulnerable assets score CVSS >= 9. The product question an OT team actually asks is
"which vulnerable assets should I patch FIRST?" So this is a risk-PRIORITIZATION alert: it
combines vulnerability severity with reachability and operational criticality into one exposure
score, and only fires for the assets that are both badly vulnerable AND exposed.

Exposure score (documented rule):
    score = (max_cvss * 4)                      # worst single CVE, 0..40
          + (min(cve_count, 50) * 0.6)          # breadth of exposure, 0..30
          + (15 if communicating else 0)        # actually on the wire = reachable
          + (10 if controller else 0)           # runs the physical process
Fires only at/above `min_score` (default 80).

Severity (tightened gate, not a pure score band):
    CRITICAL  <=> max_cvss >= 9  AND  cross-zone reachable  AND  control-plane (Level <= 2)
    otherwise a firing alert is HIGH (medium/low bands apply only if `min_score` is lowered).
The critical gate is deliberately narrow: an asset is a top remediation target only when it is
severely vulnerable, sits on the control plane, AND is exposed across Purdue zones.

Reachability joins are by IP/MAC, because the comms graph uses a DIFFERENT id space than
/components (matching on id alone returns nothing).

Pure function: (asset, vulns) pairs + reachability sets in, Alerts out.
"""
from __future__ import annotations

from app.models import Activity, Alert, Asset, Category, Severity, Status, Vulnerability
from app.alerts._util import ms_to_iso

COMPLIANCE = "NERC CIP-007 (patch & vulnerability management); NIST SP 800-82r3 (risk-based remediation)"


def communicating_keys(activities: list[Activity]) -> tuple[set[str], set[str]]:
    """Build the IP and MAC sets that appear ANYWHERE on the communication graph."""
    ips: set[str] = set()
    macs: set[str] = set()
    for a in activities:
        for node in (a.src, a.dst):
            ips.update(node.ips)
            macs.update(m.lower() for m in node.macs)
    return ips, macs


def cross_zone_keys(activities: list[Activity]) -> tuple[set[str], set[str]]:
    """IP/MAC sets for assets that talk ACROSS Purdue zones (the two endpoints differ in level)."""
    ips: set[str] = set()
    macs: set[str] = set()
    for a in activities:
        if a.src.purdue_rank is None or a.dst.purdue_rank is None:
            continue
        if a.src.purdue_rank == a.dst.purdue_rank:
            continue
        for node in (a.src, a.dst):
            ips.update(node.ips)
            macs.update(m.lower() for m in node.macs)
    return ips, macs


def exposure_score(max_cvss: float, cve_count: int, communicating: bool, is_controller: bool) -> float:
    return round(
        max_cvss * 4
        + min(cve_count, 50) * 0.6
        + (15 if communicating else 0)
        + (10 if is_controller else 0),
        1,
    )


def _severity(score: float, *, max_cvss: float, cross_zone: bool, control_plane: bool) -> Severity:
    if max_cvss >= 9 and cross_zone and control_plane:
        return Severity.critical
    if score >= 80:
        return Severity.high
    if score >= 65:
        return Severity.medium
    return Severity.low


def detect_vulnerable_exposure(
    assets_with_vulns: list[tuple[Asset, list[Vulnerability]]],
    comm_ips: set[str],
    comm_macs: set[str],
    *,
    cross_zone_ips: set[str] | None = None,
    cross_zone_macs: set[str] | None = None,
    min_score: float = 80.0,
    detected_at: str | None = None,
) -> list[Alert]:
    cross_zone_ips = cross_zone_ips or set()
    cross_zone_macs = cross_zone_macs or set()
    alerts: list[Alert] = []
    for asset, vulns in assets_with_vulns:
        if not vulns:
            continue
        max_cvss = max(v.cvss for v in vulns)
        count = len(vulns)
        asset_macs = {m.lower() for m in asset.macs}
        communicating = bool(set(asset.ips) & comm_ips or asset_macs & comm_macs)
        cross_zone = bool(set(asset.ips) & cross_zone_ips or asset_macs & cross_zone_macs)
        # control plane = a controller, or Purdue Level <= 2 (field/control, not site/IT)
        control_plane = asset.is_controller or (asset.purdue_rank is not None and asset.purdue_rank <= 2)
        score = exposure_score(max_cvss, count, communicating, asset.is_controller)
        if score < min_score:
            continue
        top = sorted(vulns, key=lambda v: v.cvss, reverse=True)[:5]
        sev = _severity(score, max_cvss=max_cvss, cross_zone=cross_zone, control_plane=control_plane)
        alerts.append(
            Alert(
                id=f"vuln-exposure-{asset.id}",
                category=Category.custom,
                title=f"High vulnerability exposure: {asset.name}",
                severity=sev,
                status=Status.active,
                detected_at=detected_at or "",
                assets=[asset],
                evidence={
                    "exposure_score": score,
                    "score_breakdown": {
                        "max_cvss_x4": round(max_cvss * 4, 1),
                        "cve_count_term": round(min(count, 50) * 0.6, 1),
                        "communicating_bonus": 15 if communicating else 0,
                        "controller_bonus": 10 if asset.is_controller else 0,
                    },
                    "cve_count": count,
                    "max_cvss": max_cvss,
                    "communicating": communicating,
                    "cross_zone_reachable": cross_zone,
                    "control_plane": control_plane,
                    "is_controller": asset.is_controller,
                    "purdue_level": asset.zone,
                    "top_cves": [{"cve": v.cve, "cvss": v.cvss, "title": v.title[:80]} for v in top],
                },
                rationale=(
                    f"{asset.name} ({asset.ip}) carries {count} known CVE(s), worst CVSS {max_cvss}, "
                    f"{'reachable across Purdue zones' if cross_zone else 'communicating'}"
                    f"{' on the control plane' if control_plane else ''}. "
                    f"Severely vulnerable + control-plane + cross-zone exposed = remediate first; an "
                    f"exploit here could directly disrupt operations."
                ),
                compliance_ref=COMPLIANCE,
                recommended_action=(
                    "Prioritise patching/mitigation for this asset; if patching is not possible, isolate it "
                    "behind a cell firewall and restrict the exposed protocols/ports."
                ),
                score=score,
            )
        )
    alerts.sort(key=lambda al: (al.severity.rank, al.score or 0), reverse=True)
    return alerts
