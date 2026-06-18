"""
API contract tests via FastAPI TestClient, driven by the SNAPSHOT fallback.

We force snapshot mode and inject a small, deterministic dataset (a skip-level violation, a
severe cross-zone controller, and a silent straggler) so the assertions hold on a fresh clone
regardless of whether local *.raw.json dumps exist. This also exercises the real resilience path.
"""
import pytest
from fastapi.testclient import TestClient

from app import service
from app.main import app
from tests.conftest import activity, component, node, vuln

BASE = 1_780_993_994_384


def _snapshot():
    # components: a severe Level-2 controller + a 3-asset cell with one silent straggler
    ctrl = component("192.168.40.2", BASE, controller=True, vuln=80, mac="11:11:11:11:11:01",
                     label="IE3400-LINE2")
    cell = [
        component("192.168.77.1", BASE, mac="11:11:11:11:11:02"),
        component("192.168.77.2", BASE, mac="11:11:11:11:11:03"),
        component("192.168.77.3", BASE - 300_000, mac="11:11:11:11:11:04"),  # silent
    ]
    comps = [ctrl, *cell]

    # activities: a skip-level (field<->IT) violation + a normal Level2<->Level0-1 link that
    # makes the controller cross-zone reachable
    field = node("192.168.40.30", level="Level 0-1", label="1734-AENTR")
    it_host = node("192.168.40.3", level="Level 3-4", label="SCADA-HOST")
    ctrl_node = node("192.168.40.2", level="Level 2", controller=True, label="IE3400-LINE2")
    acts = [
        activity(field, it_host, ["EthernetIP"]),
        activity(ctrl_node, field, ["EthernetIP", "CIP-IO"]),
    ]
    vuln_map = {ctrl["id"]: [vuln(f"CVE-2024-{i}", 10.0) for i in range(80)]}
    return comps, acts, vuln_map


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("CV_FORCE_SNAPSHOT", "1")
    monkeypatch.setattr(service, "_load_snapshot", _snapshot)
    service._cache.clear()
    with TestClient(app) as c:
        yield c
    service._cache.clear()


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_assets_shape_and_data_source(client):
    r = client.get("/assets")
    assert r.status_code == 200
    body = r.json()
    assert body["data_source"] == "snapshot"
    assert body["count"] == 4
    a = body["assets"][0]  # sorted by max_cvss desc -> the controller first
    for key in ("id", "name", "ip", "mac", "vendor", "purdue_level", "last_activity_ms", "cve_count", "max_cvss"):
        assert key in a
    assert a["max_cvss"] == 10.0 and a["cve_count"] == 80


def test_alerts_all_then_filtered(client):
    allr = client.get("/alerts").json()
    assert allr["data_source"] == "snapshot"
    cats = {a["category"] for a in allr["alerts"]}
    assert {"security", "operations", "custom"} <= cats  # one of each fires

    sec = client.get("/alerts", params={"category": "security"}).json()
    assert sec["count"] >= 1 and all(a["category"] == "security" for a in sec["alerts"])

    crit = client.get("/alerts", params={"severity": "critical"}).json()
    assert crit["count"] >= 1 and all(a["severity"] == "critical" for a in crit["alerts"])

    # filter is real: critical subset <= everything
    assert crit["count"] <= allr["count"]


def test_graph_nodes_and_edges_carry_alert_flags(client):
    g = client.get("/graph").json()
    assert g["data_source"] == "snapshot"
    nodes = [n for n in g["nodes"] if not n["data"].get("is_zone")]
    zone_nodes = [n for n in g["nodes"] if n["data"].get("is_zone")]
    assert zone_nodes  # compound zone parents emitted

    # every node/edge exposes the alert-implication fields
    assert all("alert_ids" in n["data"] and "has_alert" in n["data"] for n in nodes)
    assert all("alert_ids" in e["data"] for e in g["edges"])

    # at least one node and one edge are actually implicated, with resolvable alert ids
    flagged_nodes = [n for n in nodes if n["data"]["has_alert"]]
    flagged_edges = [e for e in g["edges"] if e["data"]["has_alert"]]
    assert flagged_nodes and flagged_edges
    alert_ids = {a["id"] for a in client.get("/alerts").json()["alerts"]}
    assert set(flagged_nodes[0]["data"]["alert_ids"]) <= alert_ids


def test_kpis_shape(client):
    k = client.get("/kpis").json()
    assert k["data_source"] == "snapshot"
    assert k["assets_monitored"] == 4
    assert k["silent_count"] >= 1
    assert k["cross_zone_count"] >= 1
    assert k["vulnerable_asset_count"] >= 1
    assert set(k["active_alerts_by_severity"]) == {"critical", "high", "medium", "low", "info"}
    assert k["reference_now"]["label"].startswith("capture end")
    assert k["reference_now"]["ms"] == BASE
