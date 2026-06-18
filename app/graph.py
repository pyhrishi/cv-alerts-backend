"""
Build a Cytoscape.js-ready communication graph from the activities, and stamp each node and
edge with the ids of the alerts that implicate it, so the UI can highlight on selection.

Alert→graph matching is by IP/MAC, not id: operations/custom alerts carry component-space
assets while the graph nodes are activity-space; IP/MAC is the stable join across both.
Zones are derived from the Purdue level and emitted as Cytoscape compound parent nodes.
"""
from __future__ import annotations

from app.models import Activity, Alert, Asset


def _alert_keysets(alert: Alert) -> tuple[set[str], set[str]]:
    ips: set[str] = set()
    macs: set[str] = set()
    for a in alert.assets:
        ips.update(i for i in a.ips if i)
        ips.update([a.ip] if a.ip else [])
        macs.update(m.lower() for m in a.macs)
        if a.mac:
            macs.add(a.mac.lower())
    return ips, macs


def _node_matches(node: Asset, ips: set[str], macs: set[str]) -> bool:
    nips = set(node.ips) | ({node.ip} if node.ip else set())
    nmacs = {m.lower() for m in node.macs} | ({node.mac.lower()} if node.mac else set())
    return bool(nips & ips or nmacs & macs)


def build_graph(activities: list[Activity], alerts: list[Alert]) -> dict:
    # precompute each alert's ip/mac footprint + a quick severity rank
    alert_keys = [(al, *_alert_keysets(al)) for al in alerts]

    nodes: dict[str, Asset] = {}
    for act in activities:
        nodes.setdefault(act.src.id, act.src)
        nodes.setdefault(act.dst.id, act.dst)

    def implicating(node_or_pair) -> list[dict]:
        hits = []
        for al, ips, macs in alert_keys:
            if node_or_pair(ips, macs):
                hits.append({"id": al.id, "category": al.category.value, "severity": al.severity.value})
        return hits

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def top_sev(hits: list[dict]) -> str | None:
        return max((h["severity"] for h in hits), key=lambda s: severity_rank[s], default=None)

    zones: set[str] = set()
    cy_nodes: list[dict] = []
    for nid, n in nodes.items():
        zone = n.zone or "unknown"
        zones.add(zone)
        hits = implicating(lambda ips, macs, nn=n: _node_matches(nn, ips, macs))
        cy_nodes.append({"data": {
            "id": nid,
            "label": n.name,
            "ip": n.ip,
            "purdue_level": zone,
            "zone": zone,
            "parent": f"zone:{zone}",
            "vendor": n.vendor,
            "is_controller": n.is_controller,
            "has_alert": bool(hits),
            "alert_ids": [h["id"] for h in hits],
            "alerts": hits,
            "max_severity": top_sev(hits),
        }})

    # compound parent nodes, one per Purdue zone
    cy_zone_nodes = [{"data": {"id": f"zone:{z}", "label": z, "is_zone": True}} for z in sorted(zones)]

    cy_edges: list[dict] = []
    for act in activities:
        sids = (set(act.src.ips) | ({act.src.ip} if act.src.ip else set()))
        smacs = {m.lower() for m in act.src.macs} | ({act.src.mac.lower()} if act.src.mac else set())
        dids = (set(act.dst.ips) | ({act.dst.ip} if act.dst.ip else set()))
        dmacs = {m.lower() for m in act.dst.macs} | ({act.dst.mac.lower()} if act.dst.mac else set())

        def edge_pred(ips, macs):  # implicated if EITHER endpoint matches the alert
            return bool((sids & ips or smacs & macs) or (dids & ips or dmacs & macs))

        hits = implicating(edge_pred)
        cy_edges.append({"data": {
            "id": act.id,
            "source": act.src.id,
            "target": act.dst.id,
            "protocols": act.protocols,
            "protocol": ", ".join(act.protocols),
            "packets": act.packets,
            "bytes": act.bytes,
            "has_alert": bool(hits),
            "alert_ids": [h["id"] for h in hits],
            "max_severity": top_sev(hits),
        }})

    return {"nodes": cy_zone_nodes + cy_nodes, "edges": cy_edges}
