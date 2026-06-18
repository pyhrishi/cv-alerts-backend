"""Custom alert — vulnerable-asset exposure scoring + tightened critical gate."""
from app.alerts.custom import _severity, detect_vulnerable_exposure, exposure_score
from app.models import Asset, Severity, Vulnerability
from tests.conftest import component, vuln

L = {"Level 0-1": 1, "Level 2": 2, "Level 3-4": 3}


def _pair(comp_dict, vulns):
    return (Asset.from_component(comp_dict, L), [Vulnerability.from_raw(v) for v in vulns])


def test_critical_requires_cvss9_crosszone_and_control_plane():
    # Level-2 controller, CVSS 10, communicating AND cross-zone -> critical.
    asset, vulns = _pair(
        component("192.168.40.2", 1_780_000_000_000, controller=True, vuln=80, mac="11:11:11:11:11:11"),
        [vuln(f"CVE-2024-{i}", 10.0) for i in range(80)],
    )
    alerts = detect_vulnerable_exposure(
        [(asset, vulns)], {"192.168.40.2"}, set(),
        cross_zone_ips={"192.168.40.2"}, min_score=80,
    )
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.critical
    assert alerts[0].evidence["cross_zone_reachable"] is True
    assert alerts[0].evidence["control_plane"] is True


def test_high_when_not_cross_zone_even_if_severe():
    # Same severe controller, communicating but NOT cross-zone -> drops to high (gate not met).
    asset, vulns = _pair(
        component("192.168.40.2", 1_780_000_000_000, controller=True, vuln=80, mac="11:11:11:11:11:11"),
        [vuln(f"CVE-2024-{i}", 10.0) for i in range(80)],
    )
    alerts = detect_vulnerable_exposure([(asset, vulns)], {"192.168.40.2"}, set(), min_score=80)
    assert alerts[0].severity == Severity.high
    assert alerts[0].evidence["cross_zone_reachable"] is False


def test_high_when_site_it_level_even_if_cross_zone():
    # Level 3-4 (site/IT, rank 3) is NOT control-plane -> at most high.
    asset, vulns = _pair(
        component("192.168.40.3", 1_780_000_000_000, level="Level 3-4", vuln=80, mac="33:33:33:33:33:33"),
        [vuln(f"CVE-2024-{i}", 10.0) for i in range(80)],
    )
    alerts = detect_vulnerable_exposure(
        [(asset, vulns)], {"192.168.40.3"}, set(), cross_zone_ips={"192.168.40.3"}, min_score=80,
    )
    assert alerts[0].severity == Severity.high
    assert alerts[0].evidence["control_plane"] is False


def test_does_not_fire_below_min_score():
    asset, vulns = _pair(
        component("192.168.40.99", 1_780_000_000_000, mac="22:22:22:22:22:22"),
        [vuln("CVE-2020-1", 4.0)],
    )
    assert detect_vulnerable_exposure([(asset, vulns)], set(), set(), min_score=80) == []


def test_exposure_score_and_severity_rule():
    # formula: cvss*4 + min(count,50)*0.6 + 15*comm + 10*controller
    assert exposure_score(10.0, 80, True, True) == 95.0          # 40 + 30 + 15 + 10
    assert exposure_score(10.0, 1, False, False) == 40.6         # 40 + 0.6
    # severity gate
    assert _severity(95, max_cvss=10, cross_zone=True, control_plane=True) == Severity.critical
    assert _severity(95, max_cvss=10, cross_zone=False, control_plane=True) == Severity.high
    assert _severity(95, max_cvss=8.5, cross_zone=True, control_plane=True) == Severity.high
    assert _severity(70, max_cvss=10, cross_zone=False, control_plane=False) == Severity.medium
    assert _severity(40, max_cvss=10, cross_zone=False, control_plane=False) == Severity.low


def test_communicating_join_uses_mac_when_ip_differs():
    asset, vulns = _pair(
        component("10.9.9.9", 1_780_000_000_000, controller=True, vuln=10, mac="de:ad:be:ef:00:01"),
        [vuln("CVE-2024-1", 9.0) for _ in range(10)],
    )
    # IP not in comms set, but MAC is -> still counts as communicating (score 67 clears a 60 floor)
    alerts = detect_vulnerable_exposure([(asset, vulns)], set(), {"de:ad:be:ef:00:01"}, min_score=60)
    assert len(alerts) == 1 and alerts[0].evidence["communicating"] is True
