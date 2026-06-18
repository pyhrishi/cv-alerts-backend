"""
The ONE module that talks to the Cyber Vision Center.

Everything else in the app calls this; nothing else imports httpx or knows the token.
Confirmed in Phase 1 (see docs/API-FINDINGS.md):
  * auth header  : x-token-id
  * API version  : /api/3.0
  * comms graph  : /presets/{id}/visualisations/activity-list  (global /flows is empty)
  * per-asset CVEs: /components/{id}/vulnerabilities
"""
from __future__ import annotations

from typing import Any

import httpx

from app.config import cv_api_token, cv_base_url

API = "/api/3.0"
ALL_DATA_PRESET = "All data"  # the preset that spans every imported capture


class CVClient:
    def __init__(self, base_url: str | None = None, token: str | None = None, timeout: float = 60.0):
        self._client = httpx.Client(
            base_url=base_url or cv_base_url(),
            headers={"x-token-id": token or cv_api_token(), "Accept": "application/json"},
            # verify=False is EXERCISE-ONLY: the Center uses a self-signed cert on a raw IP.
            # This is the single place TLS verification is disabled. Never ship to production.
            verify=False,
            timeout=timeout,
        )

    # -- context manager so callers can `with CVClient() as cv:` --------------
    def __enter__(self) -> "CVClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def _get(self, path: str, **params: Any) -> Any:
        r = self._client.get(path, params=params or None)
        r.raise_for_status()
        return r.json()

    # -- inventory / comms / risk --------------------------------------------
    def get_components(self, size: int = 100_000) -> list[dict]:
        """Full asset inventory (180 on this instance)."""
        return self._get(f"{API}/components", size=size, page=1)

    def get_presets(self) -> list[dict]:
        return self._get(f"{API}/presets")

    def resolve_preset_id(self, label: str = ALL_DATA_PRESET) -> str:
        for p in self.get_presets():
            if p.get("label") == label:
                return p["id"]
        raise LookupError(f"preset {label!r} not found")

    def get_activities(self, preset_label: str = ALL_DATA_PRESET, size: int = 100_000) -> list[dict]:
        """Aggregated component<->component links = the communication graph (global /flows is empty)."""
        pid = self.resolve_preset_id(preset_label)
        return self._get(f"{API}/presets/{pid}/visualisations/activity-list", size=size, page=1)

    def get_component_vulnerabilities(self, component_id: str) -> list[dict]:
        """CVEs matched to one asset, with CVSS + ack workflow."""
        return self._get(f"{API}/components/{component_id}/vulnerabilities")
