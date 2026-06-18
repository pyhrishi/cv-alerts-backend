"""Operations alert — silent-asset detection (per-zone-median)."""
from app.alerts.operations import _severity, detect_silent_assets
from app.models import Asset, Severity
from tests.conftest import component

L = {"Level 0-1": 1, "Level 2": 2, "Level 3-4": 3}


def _assets(dicts):
    return [Asset.from_component(d, L) for d in dicts]


def test_fires_for_asset_far_behind_its_zone_median():
    # 192.168.99.0/24 cell: two peers fresh, one stopped ~300s earlier than the median.
    base = 1_780_000_000_000
    cell = _assets([
        component("192.168.99.1", base, mac="00:00:00:00:00:01"),
        component("192.168.99.2", base, mac="00:00:00:00:00:02"),
        component("192.168.99.3", base - 300_000, mac="00:00:00:00:00:03"),  # straggler
    ])
    alerts = detect_silent_assets(cell, min_seconds_behind_zone_median=60)
    assert len(alerts) == 1
    assert alerts[0].assets[0].ip == "192.168.99.3"
    assert alerts[0].evidence["seconds_behind_zone_median"] >= 60
    assert alerts[0].category.value == "operations"


def test_does_not_fire_when_whole_cell_stops_together():
    # Capture-end case: every asset shares the same last-seen -> median == each -> nobody behind.
    t = 1_780_000_000_000
    cell = _assets([component(f"192.168.88.{i}", t, mac=f"00:00:00:00:01:0{i}") for i in range(1, 5)])
    assert detect_silent_assets(cell, min_seconds_behind_zone_median=60) == []


def test_does_not_fire_for_tiny_zone_below_min_size():
    base = 1_780_000_000_000
    cell = _assets([
        component("10.0.0.1", base, mac="00:00:00:00:02:01"),
        component("10.0.0.2", base - 500_000, mac="00:00:00:00:02:02"),
    ])
    assert detect_silent_assets(cell, min_seconds_behind_zone_median=60, min_zone_size=3) == []


def test_severity_rule_is_derived_from_lag_and_role():
    # documented rule: tiers by seconds-behind, +1 level if controller
    assert _severity(50, False) == Severity.low
    assert _severity(130, False) == Severity.medium
    assert _severity(200, False) == Severity.high
    assert _severity(200, True) == Severity.critical      # controller bump
    assert _severity(130, True) == Severity.high           # controller bump


def test_parses_real_committed_components(real_components):
    assets = _assets(real_components)
    assert assets and all(a.id for a in assets)
    # the real sample includes a Siemens IO module with an IP and a last-seen timestamp
    assert any(a.ip and a.last_seen_ms for a in assets)
