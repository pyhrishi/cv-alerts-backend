"""Security alert — Purdue zone-and-conduit policy violations."""
from app.alerts.security import detect_cross_zone_violations
from app.models import Activity
from tests.conftest import activity, node

L = {"Level 0-1": 1, "Level 2": 2, "Level 3-4": 3}


def _acts(raw, policy):
    return [Activity.from_raw(a, policy.purdue_levels, tuple(policy.controller_tags)) for a in raw]


def test_fires_skip_level_field_to_it(policy):
    # Level 0-1 field device talking straight to a Level 3-4 host (skips Level 2) -> critical.
    field = node("192.168.40.30", level="Level 0-1", label="1734-AENTR IO")
    it_host = node("192.168.40.3", level="Level 3-4", label="SCADA-HOST")
    alerts = detect_cross_zone_violations(_acts([activity(field, it_host, ["EthernetIP"])], policy), policy)
    skip = [a for a in alerts if a.evidence["rule"] == "SKIP_LEVEL"]
    assert len(skip) == 1
    assert skip[0].severity.value == "critical"
    assert skip[0].evidence["level_gap"] == 2


def test_does_not_fire_for_adjacent_levels(policy):
    # Level 0-1 <-> Level 2 (IO <-> PLC) is the normal conduit; clean protocols -> no alert.
    io = node("192.168.40.31", level="Level 0-1")
    plc = node("192.168.40.10", level="Level 2", controller=True)
    alerts = detect_cross_zone_violations(_acts([activity(io, plc, ["EthernetIP", "CIP-IO"])], policy), policy)
    assert alerts == []


def test_insecure_cleartext_to_controller_is_high(policy):
    cam = node("192.168.50.40", level="Level 0-1", label="axis-cam")
    hub = node("192.168.50.5", level="Level 2", controller=True, label="INSPECTION-HUB")
    alerts = detect_cross_zone_violations(_acts([activity(cam, hub, ["HTTP"])], policy), policy)
    insec = [a for a in alerts if a.evidence["rule"] == "INSECURE_PROTOCOL"]
    assert insec and insec[0].severity.value == "high"   # cleartext == high (rule-derived)
    assert "HTTP" in insec[0].evidence["protocols"]


def test_broadcast_peer_is_ignored(policy):
    # SMB to the subnet broadcast is normal Windows chatter, not an asset-to-asset finding.
    hub = node("192.168.50.5", level="Level 2", controller=True, label="HMI")
    bcast = node("192.168.50.255", label="broadcast")
    alerts = detect_cross_zone_violations(_acts([activity(hub, bcast, ["SMB", "Netbios"])], policy), policy)
    assert alerts == []


def test_parses_real_activities_without_false_skip_level(policy, real_activities):
    # The real sample is all IO<->PLC (adjacent); none should be a skip-level violation.
    alerts = detect_cross_zone_violations(_acts(real_activities, policy), policy)
    assert all(a.evidence["rule"] != "SKIP_LEVEL" for a in alerts)
