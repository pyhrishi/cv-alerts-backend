"""
SECURITY alert — "Unexpected / unauthorized communication" (Purdue zone-and-conduit policy).

Maps to the assignment's "unexpected asset connecting" example. Because CV's native baselines
and events are empty on this instance (see docs/API-FINDINGS.md), the expected state is authored
by us in app/policy/expected_state_policy.yaml. This detector reads that policy and flags
communication relationships that violate it.

Rules:
  R1 SKIP_LEVEL   - traffic between non-adjacent Purdue levels (e.g. field <-> site/IT, skipping
                    the control layer). Grouped by the supervisory host doing the reaching, so a
                    host bypassing the conduit to many field devices is ONE actionable alert.
  R2 INSECURE_PROTOCOL - cleartext / IT protocol to or from a controller, grouped by the controller.
  R3 EXTERNAL_COMMS    - a conversation with an address outside all OT networks.
  R4 UNKNOWN_VENDOR    - a controller talking to an asset whose vendor is not on the allowlist.

Broadcast/multicast endpoints (e.g. x.x.x.255, 224.0.0.0/4) are ignored: they are not real assets
and would otherwise flood the alert with normal Windows/ARP chatter.

Pure function: activities + policy in, Alerts out.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict

from app.models import Activity, Alert, Asset, Category, Policy, Severity, Status
from app.alerts._util import ms_to_iso

COMPLIANCE_ZONE = "NIST SP 800-82r3 (zones & conduits); IEC 62443; NERC CIP-005 (electronic security perimeter)"
COMPLIANCE_PROTO = "NIST SP 800-82r3 (secure protocols / least functionality); NIS2 risk-management measures"


def _is_broadcast_multicast(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_multicast or ip.endswith(".255") or addr == ipaddress.ip_address("255.255.255.255")


def detect_cross_zone_violations(activities: list[Activity], policy: Policy) -> list[Alert]:
    adjacency = policy.adjacency_set
    crit_gap = int(policy.severity.get("skip_level_gap_for_critical", 2))
    known = policy.known_vendor_set
    alerts: list[Alert] = []

    # ---- R1: SKIP_LEVEL, grouped by the supervisory (higher-rank) host -------
    # group key = supervisory asset id; value aggregates the field peers it reached
    skip_groups: dict[str, dict] = {}
    for act in activities:
        s, d = act.src, act.dst
        if s.purdue_rank is None or d.purdue_rank is None:
            continue
        if _is_broadcast_multicast(s.ip) or _is_broadcast_multicast(d.ip):
            continue
        pair = frozenset({s.purdue_rank, d.purdue_rank})
        if len(pair) != 2 or pair in adjacency:
            continue
        sup, field = (s, d) if s.purdue_rank > d.purdue_rank else (d, s)
        g = skip_groups.setdefault(sup.id, {"sup": sup, "peers": {}, "protocols": set(),
                                            "gap": 0, "last": act.last_seen_ms})
        g["peers"][field.id] = field
        g["protocols"].update(act.protocols)
        g["gap"] = max(g["gap"], abs(s.purdue_rank - d.purdue_rank))
        g["last"] = max(g["last"] or 0, act.last_seen_ms or 0)

    for g in skip_groups.values():
        sup, peers = g["sup"], list(g["peers"].values())
        sev = Severity.critical if g["gap"] >= crit_gap else Severity.high
        peer_names = ", ".join(p.name for p in peers[:5]) + (" …" if len(peers) > 5 else "")
        alerts.append(
            Alert(
                id=f"sec-skiplevel-{sup.id}",
                category=Category.security,
                title=f"Cross-zone violation: {sup.zone} host {sup.name} reaches {len(peers)} field device(s) directly",
                severity=sev,
                status=Status.active,
                detected_at=ms_to_iso(g["last"]) or "",
                assets=[sup, *peers],
                evidence={
                    "rule": "SKIP_LEVEL",
                    "supervisory_host": {"name": sup.name, "ip": sup.ip, "level": sup.zone},
                    "field_peers": [{"name": p.name, "ip": p.ip, "level": p.zone} for p in peers],
                    "peer_count": len(peers),
                    "level_gap": g["gap"],
                    "protocols": sorted(g["protocols"]),
                },
                rationale=(
                    f"{sup.name} ({sup.zone}) communicates directly with {len(peers)} field device(s) "
                    f"[{peer_names}], skipping the control layer. The Purdue model requires traffic to "
                    f"cross adjacent zones through a conduit; a site/IT host reaching field devices "
                    f"directly is a segmentation breach and a lateral-movement path toward physical process."
                ),
                compliance_ref=COMPLIANCE_ZONE,
                recommended_action=(
                    "Confirm whether this path is sanctioned. If not, block it at the cell/zone firewall "
                    "and route the traffic through the Level-2 controller conduit."
                ),
            )
        )

    # ---- R2: INSECURE_PROTOCOL, grouped by the controller --------------------
    insec_groups: dict[tuple, dict] = {}
    for act in activities:
        if not (act.src.is_controller or act.dst.is_controller):
            continue
        ctrl, peer = (act.src, act.dst) if act.src.is_controller else (act.dst, act.src)
        if _is_broadcast_multicast(peer.ip):
            continue
        protos = set(act.protocols)
        cleartext = sorted(protos & policy.cleartext_app)
        it_proto = sorted(protos & policy.it_in_ot)
        if not (cleartext or it_proto):
            continue
        kind = "cleartext" if cleartext else "enterprise-IT"
        key = (ctrl.id, kind)
        g = insec_groups.setdefault(key, {"ctrl": ctrl, "peers": {}, "protos": set(),
                                          "kind": kind, "last": act.last_seen_ms})
        g["peers"][peer.id] = peer
        g["protos"].update(cleartext or it_proto)
        g["last"] = max(g["last"] or 0, act.last_seen_ms or 0)

    for (ctrl_id, kind), g in insec_groups.items():
        ctrl, peers = g["ctrl"], list(g["peers"].values())
        bad = sorted(g["protos"])
        sev = Severity.high if kind == "cleartext" else Severity.medium
        alerts.append(
            Alert(
                id=f"sec-insecure-{ctrl_id}-{kind}",
                category=Category.security,
                title=f"{kind.title()} protocol on controller {ctrl.name}: {', '.join(bad)}",
                severity=sev,
                status=Status.active,
                detected_at=ms_to_iso(g["last"]) or "",
                assets=[ctrl, *peers],
                evidence={
                    "rule": "INSECURE_PROTOCOL",
                    "controller": {"name": ctrl.name, "ip": ctrl.ip, "level": ctrl.zone},
                    "protocols": bad,
                    "peer_count": len(peers),
                    "peers": [{"name": p.name, "ip": p.ip} for p in peers[:8]],
                },
                rationale=(
                    f"Controller {ctrl.name} exchanges {kind} protocol(s) {bad} with {len(peers)} peer(s). "
                    f"Cleartext/legacy IT protocols on control assets expose credentials and commands and "
                    f"widen the attack surface against equipment that runs the physical process."
                ),
                compliance_ref=COMPLIANCE_PROTO,
                recommended_action=(
                    "Disable or tunnel the protocol (HTTP->HTTPS, remove SMB/NetBIOS from OT) and restrict "
                    "management to a hardened jump host."
                ),
            )
        )

    # ---- R3: EXTERNAL_COMMS / R4: UNKNOWN_VENDOR (per relationship) ----------
    seen: set[tuple] = set()
    for act in activities:
        s, d = act.src, act.dst
        ext = next((ip for ip in (s.ip, d.ip) if policy.is_external_ip(ip)), None)
        if ext and ("EXT", ext) not in seen:
            seen.add(("EXT", ext))
            alerts.append(
                Alert(
                    id=f"sec-external-{ext.replace('.', '-')}",
                    category=Category.security,
                    title=f"External conversation with {ext} ({s.name} ↔ {d.name})",
                    severity=Severity.high,
                    status=Status.active,
                    detected_at=ms_to_iso(act.last_seen_ms) or "",
                    assets=[s, d],
                    evidence={"rule": "EXTERNAL_COMMS", "external_ip": ext, "protocols": act.protocols},
                    rationale=(
                        f"A conversation involves {ext}, outside every defined OT network. Unexpected "
                        f"egress/ingress from the OT cell can indicate exfiltration, remote C2, or an "
                        f"unmanaged device bridged into the process network."
                    ),
                    compliance_ref=COMPLIANCE_ZONE,
                    recommended_action="Identify the external endpoint; if not an approved jump host, block and investigate.",
                )
            )
        for ctrl, other in ((s, d), (d, s)):
            if ctrl.is_controller and other.vendor and other.vendor not in known:
                if ("VEN", ctrl.id, other.vendor) in seen:
                    continue
                seen.add(("VEN", ctrl.id, other.vendor))
                alerts.append(
                    Alert(
                        id=f"sec-vendor-{ctrl.id}",
                        category=Category.security,
                        title=f"Unknown-vendor device on controller conduit: {other.name} -> {ctrl.name}",
                        severity=Severity.medium,
                        status=Status.active,
                        detected_at=ms_to_iso(act.last_seen_ms) or "",
                        assets=[ctrl, other],
                        evidence={"rule": "UNKNOWN_VENDOR", "unknown_vendor": other.vendor,
                                  "controller": ctrl.name, "protocols": act.protocols},
                        rationale=(
                            f"{other.name} (vendor '{other.vendor}', not on the allowlist) communicates with "
                            f"controller {ctrl.name}. An unrecognised vendor on a control conduit may be rogue "
                            f"or unmanaged hardware."
                        ),
                        compliance_ref=COMPLIANCE_ZONE,
                        recommended_action="Verify the device against the asset register; remove or authorise it explicitly.",
                    )
                )
                break

    alerts.sort(key=lambda al: al.severity.rank, reverse=True)
    return alerts
