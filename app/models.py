"""
Typed domain models + parsers for Cyber Vision data.

Raw CV JSON is messy and inconsistent (a component's `ip` is a string; an activity
endpoint's `ip` is a list). These models normalize it once, so the detectors operate on
clean, typed objects and never touch raw dicts. Parsing lives here; detection lives in
app/alerts/*. Nothing here makes a network call.
"""
from __future__ import annotations

import ipaddress
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

# --- enums -------------------------------------------------------------------
class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    @classmethod
    def from_rank(cls, r: int) -> "Severity":
        r = max(0, min(4, r))
        return [cls.info, cls.low, cls.medium, cls.high, cls.critical][r]

    def bumped(self, by: int = 1) -> "Severity":
        return Severity.from_rank(self.rank + by)


class Category(str, Enum):
    security = "security"
    operations = "operations"
    custom = "custom"


class Status(str, Enum):
    active = "active"
    acknowledged = "acknowledged"
    resolved = "resolved"


# --- tag helpers (component tags and activity-node tags share this shape) -----
def _purdue_label(tags: list[dict] | None) -> str | None:
    for t in tags or []:
        cat = (t.get("category") or {}).get("label", "")
        if cat.startswith("Device - Level"):
            return cat.replace("Device - ", "")
    return None


def _vendor_from_tags(tags: list[dict] | None) -> str | None:
    for t in tags or []:
        if (t.get("category") or {}).get("label") == "System":
            return t.get("label")
    return None


def _has_controller_tag(tags: list[dict] | None, controller_tags: tuple[str, ...] = ("PLC", "Controller")) -> bool:
    for t in tags or []:
        if t.get("id") in controller_tags or t.get("label") in controller_tags:
            return True
    return False


# --- Asset -------------------------------------------------------------------
class Asset(BaseModel):
    id: str
    name: str
    ip: str | None = None
    mac: str | None = None
    ips: list[str] = Field(default_factory=list)
    macs: list[str] = Field(default_factory=list)
    vendor: str | None = None
    zone: str = "unknown"          # Purdue level label, or "unknown"
    purdue_rank: int | None = None
    type: str = ""                 # device role / label
    is_controller: bool = False
    last_seen_ms: int | None = None
    first_seen_ms: int | None = None
    vuln_count: int = 0

    @property
    def subnet(self) -> str | None:
        if not self.ip:
            return None
        try:
            return str(ipaddress.ip_network(self.ip + "/24", strict=False))
        except ValueError:
            return None

    @staticmethod
    def _rank(label: str | None, levels: dict[str, int]) -> int | None:
        return levels.get(label) if label else None

    @classmethod
    def from_component(cls, c: dict, levels: dict[str, int], controller_tags=("PLC", "Controller")) -> "Asset":
        props = {p["key"]: p["value"] for p in c.get("normalizedProperties", [])}
        label = _purdue_label(c.get("tags"))
        ip = c.get("ip") or props.get("ip") or None
        mac = c.get("mac") or props.get("mac") or None
        rank = cls._rank(label, levels)
        return cls(
            id=c["id"],
            name=c.get("label") or ip or c["id"],
            ip=ip or None,
            mac=(mac or None),
            ips=[ip] if ip else [],
            macs=[mac.lower()] if mac else [],
            vendor=props.get("vendor-name") or _vendor_from_tags(c.get("tags")),
            zone=label or "unknown",
            purdue_rank=rank,
            type=props.get("name") or c.get("label") or "",
            is_controller=_has_controller_tag(c.get("tags"), controller_tags) or rank == levels.get("Level 2"),
            last_seen_ms=c.get("lastActivity"),
            first_seen_ms=c.get("firstActivity"),
            vuln_count=c.get("vulnerabilitiesCount", 0),
        )

    @classmethod
    def from_activity_node(cls, n: dict, levels: dict[str, int], controller_tags=("PLC", "Controller")) -> "Asset":
        label = _purdue_label(n.get("tags"))
        rank = cls._rank(label, levels)
        ips = [i for i in (n.get("ip") or []) if i]
        macs = [m.lower() for m in (n.get("mac") or []) if m]
        return cls(
            id=n["id"],
            name=n.get("label") or (ips[0] if ips else n["id"]),
            ip=ips[0] if ips else None,
            mac=macs[0] if macs else None,
            ips=ips,
            macs=macs,
            vendor=_vendor_from_tags(n.get("tags")),
            zone=label or "unknown",
            purdue_rank=rank,
            type=n.get("label") or "",
            is_controller=_has_controller_tag(n.get("tags"), controller_tags) or rank == levels.get("Level 2"),
        )


class Vulnerability(BaseModel):
    cve: str
    cvss: float = 0.0
    cvss_version: float | None = None
    title: str = ""

    @classmethod
    def from_raw(cls, v: dict) -> "Vulnerability":
        return cls(
            cve=v.get("cve", "") or v.get("id", ""),
            cvss=float(v.get("CVSS") or 0.0),
            cvss_version=v.get("CVSSVersion"),
            title=v.get("title", ""),
        )


class Activity(BaseModel):
    id: str
    src: Asset
    dst: Asset
    protocols: list[str] = Field(default_factory=list)
    last_seen_ms: int | None = None
    first_seen_ms: int | None = None
    packets: int = 0
    bytes: int = 0

    @classmethod
    def from_raw(cls, a: dict, levels: dict[str, int], controller_tags=("PLC", "Controller")) -> "Activity":
        protos = [t["label"] for t in a.get("tags", []) if (t.get("category") or {}).get("label") == "Protocol"]
        return cls(
            id=a["id"],
            src=Asset.from_activity_node(a["left"], levels, controller_tags),
            dst=Asset.from_activity_node(a["right"], levels, controller_tags),
            protocols=protos,
            last_seen_ms=a.get("lastActivity"),
            first_seen_ms=a.get("firstActivity"),
            packets=a.get("packetsCount", 0),
            bytes=a.get("bytesCount", 0),
        )


# --- graph (for the comms-relations visualization later) ---------------------
class GraphNode(BaseModel):
    id: str
    label: str
    ip: str | None = None
    zone: str = "unknown"
    vendor: str | None = None
    vuln_count: int = 0


class GraphEdge(BaseModel):
    source: str
    target: str
    protocols: list[str] = Field(default_factory=list)
    packets: int = 0
    bytes: int = 0


# --- the Alert contract (matches .claude/skills/alert-design) -----------------
class Alert(BaseModel):
    id: str
    category: Category
    title: str
    severity: Severity
    status: Status = Status.active
    detected_at: str                      # ISO8601
    assets: list[Asset] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    compliance_ref: str | None = None
    recommended_action: str = ""
    score: float | None = None            # custom alert exposure score (optional)


# --- the authored OT policy (drives the security alert) ----------------------
DEFAULT_POLICY_PATH = Path(__file__).resolve().parent / "policy" / "expected_state_policy.yaml"


class Policy(BaseModel):
    version: int = 1
    reference_now_strategy: str = "max_last_activity"
    purdue_levels: dict[str, int]
    allowed_level_adjacencies: list[list[int]]
    ot_networks: list[str]
    non_external_prefixes: list[str] = Field(default_factory=list)
    controller_tags: list[str]
    controller_level: str
    known_vendors: list[str]
    insecure_protocols: dict[str, list[str]]
    severity: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path = DEFAULT_POLICY_PATH) -> "Policy":
        return cls(**yaml.safe_load(Path(path).read_text(encoding="utf-8")))

    # -- convenience accessors used by the security detector ------------------
    @property
    def adjacency_set(self) -> set[frozenset[int]]:
        return {frozenset(pair) for pair in self.allowed_level_adjacencies}

    @property
    def known_vendor_set(self) -> set[str]:
        return {v.strip() for v in self.known_vendors}

    @property
    def cleartext_app(self) -> set[str]:
        return set(self.insecure_protocols.get("cleartext_app", []))

    @property
    def it_in_ot(self) -> set[str]:
        return set(self.insecure_protocols.get("it_in_ot", []))

    def is_external_ip(self, ip: str | None) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for pfx in self.non_external_prefixes:
            if addr in ipaddress.ip_network(pfx):
                return False
        for net in self.ot_networks:
            if addr in ipaddress.ip_network(net):
                return False
        return True
