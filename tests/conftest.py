"""
Test fixtures + builders.

Builders mirror the EXACT shape of the real CV JSON captured in docs/api-samples/ (component
dicts, activity-node dicts, vulnerability dicts), so the detectors are exercised against the
same structures they see in production. `real_*` fixtures load the committed trimmed samples to
prove parsing works on untouched real data.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.models import Policy

SAMPLES = Path(__file__).resolve().parents[1] / "docs" / "api-samples"


# --- builders (real CV shapes) -----------------------------------------------
def component(ip, last_ms, *, level=None, controller=False, vuln=0, mac="00:11:22:33:44:55",
              vendor="Rockwell Automation", cid=None, label=None):
    tags = []
    if level:
        tags.append({"id": "LVL", "label": level, "category": {"label": f"Device - {level}"}})
    if controller:
        tags.append({"id": "PLC", "label": "Controller", "category": {"label": "Device - Level 2"}})
    return {
        "id": cid or f"c-{ip}-{mac}",
        "label": label or ip,
        "ip": ip,
        "mac": mac,
        "lastActivity": last_ms,
        "firstActivity": last_ms - 5000,
        "vulnerabilitiesCount": vuln,
        "tags": tags,
        "normalizedProperties": [
            {"key": "ip", "value": ip},
            {"key": "mac", "value": mac},
            {"key": "vendor-name", "value": vendor},
        ],
    }


def node(ip, *, level=None, controller=False, vendor=None, mac="aa:bb:cc:dd:ee:ff", label=None, nid=None):
    tags = []
    if level:
        tags.append({"id": "LVL", "label": level, "type": "component", "category": {"label": f"Device - {level}"}})
    if controller:
        tags.append({"id": "PLC", "label": "Controller", "type": "component", "category": {"label": "Device - Level 2"}})
    if vendor:
        tags.append({"id": "VEN", "label": vendor, "type": "component", "category": {"label": "System"}})
    return {
        "id": nid or f"n-{ip}-{mac}",
        "label": label or ip,
        "ip": [ip],
        "mac": [mac],
        "tags": tags,
    }


def activity(left, right, protocols, last_ms=1780993994384, packets=100, nbytes=1000):
    return {
        "id": f"{left['id']}_{right['id']}",
        "left": left,
        "right": right,
        "tags": [{"label": p, "type": "flow", "category": {"label": "Protocol"}} for p in protocols],
        "lastActivity": last_ms,
        "firstActivity": last_ms - 5000,
        "packetsCount": packets,
        "bytesCount": nbytes,
    }


def vuln(cve, cvss, title="x"):
    return {"cve": cve, "CVSS": cvss, "CVSSVersion": 3.1, "title": title}


# --- fixtures ----------------------------------------------------------------
@pytest.fixture(scope="session")
def policy() -> Policy:
    return Policy.load()


@pytest.fixture(scope="session")
def levels(policy) -> dict:
    return policy.purdue_levels


def _load_sample(name):
    obj = json.loads((SAMPLES / name).read_text(encoding="utf-8"))
    return obj if isinstance(obj, list) else obj.get("sample", [])


@pytest.fixture(scope="session")
def real_components():
    return _load_sample("components.json")


@pytest.fixture(scope="session")
def real_activities():
    return _load_sample("activities_alldata.json")
