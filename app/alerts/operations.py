"""
OPERATIONS alert — "Asset went silent".

Maps to the assignment's "sudden stop of device communication" example.

Detection idea (honest about a STATIC capture):
  This Center holds imported PCAPs, so there is no live clock — every timestamp sits inside one
  capture window. A naive "no traffic for N seconds vs the global capture end" flags ~all 180
  assets, because whole capture cells stop together at the end of their PCAP.

  Instead we look for an asset that fell silent WHILE ITS PEERS KEPT TALKING. We group assets by
  /24 subnet (an OT "cell"), take the cell's MEDIAN last-seen time, and flag assets whose own
  last-seen is more than `min_seconds_behind_zone_median` behind that median. A cell that stopped
  all at once moves its median with it, so it is NOT flagged — only genuine stragglers are.

This is a pure function: assets in, Alerts out. No network, no globals.
"""
from __future__ import annotations

import statistics
from collections import defaultdict

from app.models import Alert, Asset, Category, Severity, Status
from app.alerts._util import ms_to_iso

COMPLIANCE = "NIST SP 800-82r3 (continuous OT monitoring); NERC CIP-007 (security event monitoring)"


def _severity(seconds_behind: float, is_controller: bool) -> Severity:
    """Documented rule: magnitude tiers, bumped one level for a controller (operationally critical)."""
    if seconds_behind >= 180:
        base = Severity.high
    elif seconds_behind >= 120:
        base = Severity.medium
    else:
        base = Severity.low
    return base.bumped(1) if is_controller else base


def detect_silent_assets(
    assets: list[Asset],
    *,
    min_seconds_behind_zone_median: float = 60.0,
    min_zone_size: int = 3,
    reference_now_ms: int | None = None,
) -> list[Alert]:
    timestamped = [a for a in assets if a.last_seen_ms and a.subnet]
    if not timestamped:
        return []

    ref = reference_now_ms or max(a.last_seen_ms for a in timestamped)
    iso_now = ms_to_iso(ref)

    by_zone: dict[str, list[Asset]] = defaultdict(list)
    for a in timestamped:
        by_zone[a.subnet].append(a)

    alerts: list[Alert] = []
    for subnet, members in by_zone.items():
        if len(members) < min_zone_size:
            continue  # too few peers to define "normal" for the cell
        zone_median = statistics.median(m.last_seen_ms for m in members)
        for a in members:
            seconds_behind = (zone_median - a.last_seen_ms) / 1000.0
            if seconds_behind <= min_seconds_behind_zone_median:
                continue
            sev = _severity(seconds_behind, a.is_controller)
            alerts.append(
                Alert(
                    id=f"ops-silent-{a.id}",
                    category=Category.operations,
                    # several CV components can share an IP (distinct MACs / interfaces); show the
                    # MAC so each silent entity is unambiguous in the operator's list.
                    title=f"Asset went silent: {a.name}" + (f" [{a.mac}]" if a.mac else ""),
                    severity=sev,
                    status=Status.active,
                    detected_at=iso_now,
                    assets=[a],
                    evidence={
                        "subnet": subnet,
                        "zone_peers": len(members),
                        "last_seen": ms_to_iso(a.last_seen_ms),
                        "zone_median_last_seen": ms_to_iso(int(zone_median)),
                        "seconds_behind_zone_median": round(seconds_behind, 1),
                        "is_controller": a.is_controller,
                        "purdue_level": a.zone,
                    },
                    rationale=(
                        f"{a.name} ({a.ip}) stopped communicating ~{round(seconds_behind)}s before the "
                        f"rest of its subnet {subnet}, which kept exchanging traffic. In OT a device that "
                        f"goes quiet while peers continue can mean a failed controller/sensor, a pulled "
                        f"cable, or an attacker silencing a device — all of which interrupt the process."
                    ),
                    compliance_ref=COMPLIANCE,
                    recommended_action=(
                        "Verify the device is powered and reachable (ping/operator HMI). If it is a "
                        "controller, check process state before it drifts. If the silence is unexpected, "
                        "raise an operations ticket and inspect the switch port / link."
                    ),
                    score=round(seconds_behind, 1),
                )
            )
    # most-silent first
    alerts.sort(key=lambda al: al.evidence["seconds_behind_zone_median"], reverse=True)
    return alerts
