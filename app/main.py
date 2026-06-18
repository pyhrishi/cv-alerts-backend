"""
FastAPI surface for the Cyber Vision alert engine.

This layer is thin: every endpoint reads ONE cached bundle (app/service.get_bundle) and shapes
it. The bundle fetches CV via the single cv_client, parses into Pydantic models, and runs the
three detectors — with a graceful snapshot fallback if the Center is unreachable. The CV token
never leaves the server; CORS is locked to ALLOWED_ORIGINS (no '*').
"""
from __future__ import annotations

from collections import Counter

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

from app import config
from app.graph import build_graph
from app.service import Bundle, get_bundle

app = FastAPI(
    title="Cyber Vision Alert API",
    version="1.0.0",
    description="Secure proxy + alert engine in front of a Cisco Cyber Vision Center.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.allowed_origins(),  # tight allowlist; never '*'
    allow_methods=["GET"],
    allow_headers=["*"],
)


def _reference_now(b: Bundle) -> dict:
    return {
        "ms": b.reference_now_ms,
        "iso": b.reference_now_iso,
        "label": "capture end (newest lastActivity in the dataset; static PCAP import)",
    }


@app.get("/healthz")
def healthz() -> dict:
    # Cheap liveness probe — does NOT touch CV or build the bundle (cold-start safe).
    return {"status": "ok"}


@app.get("/")
def root() -> dict:
    return {
        "service": "cv-alerts-backend",
        "endpoints": ["/healthz", "/assets", "/alerts", "/graph", "/kpis"],
        "docs": "/docs",
    }


@app.get("/assets")
def assets() -> dict:
    b = get_bundle()
    items = []
    for a in b.assets:
        items.append({
            "id": a.id,
            "name": a.name,
            "ip": a.ip,
            "mac": a.mac,
            "vendor": a.vendor,
            "purdue_level": a.zone,
            "is_controller": a.is_controller,
            "last_activity_ms": a.last_seen_ms,
            "cve_count": b.cve_count.get(a.id, a.vuln_count),
            "max_cvss": b.max_cvss.get(a.id, 0.0),
        })
    items.sort(key=lambda x: (x["max_cvss"], x["cve_count"]), reverse=True)
    return {"data_source": b.data_source, "reference_now": _reference_now(b),
            "count": len(items), "assets": items}


@app.get("/alerts")
def alerts(
    category: str | None = Query(default=None, pattern="^(security|operations|custom)$"),
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low|info)$"),
) -> dict:
    b = get_bundle()
    if category:
        selected = list(b.alerts.get(category, []))
    else:
        selected = b.all_alerts
    if severity:
        selected = [a for a in selected if a.severity.value == severity]
    selected = sorted(selected, key=lambda a: a.severity.rank, reverse=True)
    return {
        "data_source": b.data_source,
        "reference_now": _reference_now(b),
        "count": len(selected),
        "filters": {"category": category, "severity": severity},
        "alerts": [a.model_dump() for a in selected],
    }


@app.get("/graph")
def graph() -> dict:
    b = get_bundle()
    g = build_graph(b.activities, b.all_alerts)
    return {"data_source": b.data_source, "reference_now": _reference_now(b),
            "node_count": len(g["nodes"]), "edge_count": len(g["edges"]), **g}


@app.get("/kpis")
def kpis() -> dict:
    b = get_bundle()
    by_sev = Counter(a.severity.value for a in b.all_alerts)
    vulnerable_assets = sum(1 for cid, n in b.cve_count.items() if n > 0)
    return {
        "data_source": b.data_source,
        "reference_now": _reference_now(b),
        "assets_monitored": len(b.assets),
        "active_alerts_total": len(b.all_alerts),
        "active_alerts_by_severity": {
            s: by_sev.get(s, 0) for s in ("critical", "high", "medium", "low", "info")
        },
        "active_alerts_by_category": {k: len(v) for k, v in b.alerts.items()},
        "silent_count": len(b.alerts.get("operations", [])),
        "cross_zone_count": len(b.alerts.get("security", [])),
        "vulnerable_asset_count": vulnerable_assets,
    }
