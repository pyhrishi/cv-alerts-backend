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
Severity band:  >=90 critical | >=80 high | >=65 medium | else low.
Fires only at/above `min_score` (default 80 -> the high/critical band).

"communicating" is decided by joining the asset's IP/MAC to the activity graph, because the
comms endpoints use a DIFFERENT id space than /components (matching on id alone returns nothing).

Pure function: (asset, vulns) pairs + the set of communicating IPs/MACs in, Alerts out.
"""
from __future__ import annotations

from app.models import Activity, Alert, Asset, Category, Severity, Status, Vulnerability
from app.alerts._util import ms_to_iso

COMPLIANCE = "NERC CIP-007 (patch & vulnerability management); NIST SP 800-82r3 (risk-based remediation)"


def communicating_keys(activities: list[Activity]) -> tuple[set[str], set[str]]:
    """Build the IP and MAC sets that actually appear on the communication graph."""
    ips: set[str] = set()
    macs: set[str] = set()
    for a in activities:
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


def _severity(score: float) -> Severity:
    if score >= 90:
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
    min_score: float = 80.0,
    detected_at: str | None = None,
) -> list[Alert]:
    alerts: list[Alert] = []
    for asset, vulns in assets_with_vulns:
        if not vulns:
            continue
        max_cvss = max(v.cvss for v in vulns)
        count = len(vulns)
        communicating = bool(set(asset.ips) & comm_ips or {m.lower() for m in asset.macs} & comm_macs)
        score = exposure_score(max_cvss, count, communicating, asset.is_controller)
        if score < min_score:
            continue
        top = sorted(vulns, key=lambda v: v.cvss, reverse=True)[:5]
        sev = _severity(score)
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
                    "is_controller": asset.is_controller,
                    "purdue_level": asset.zone,
                    "top_cves": [{"cve": v.cve, "cvss": v.cvss, "title": v.title[:80]} for v in top],
                },
                rationale=(
                    f"{asset.name} ({asset.ip}) carries {count} known CVE(s), worst CVSS {max_cvss}, and is "
                    f"{'actively communicating on the network' if communicating else 'present but quiet'}"
                    f"{' and is a controller running the process' if asset.is_controller else ''}. "
                    f"Vulnerable + reachable + critical = the assets to remediate first; an exploit here "
                    f"could directly disrupt operations."
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
