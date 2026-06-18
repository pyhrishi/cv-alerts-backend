"""
Phase 1 — Cyber Vision Center API discovery.

Goal: prove we can reach the Center programmatically and map what data exists.
This script is READ-ONLY against the Center (GET requests only).

Safety rules enforced here:
  * The API token is loaded from .env and is NEVER printed, logged, or written to
    any sample file. We only ever print HTTP status codes and trimmed response bodies.
  * TLS verification is OFF because the Center uses a self-signed cert on a raw IP.
    This is EXERCISE-ONLY and is isolated to the single client factory below.

Usage:
    .venv/Scripts/python.exe scripts/discover.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import httpx
from dotenv import dotenv_values

# --- Paths -------------------------------------------------------------------
BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_DIR.parent
SAMPLES_DIR = REPO_ROOT / "docs" / "api-samples"

# --- Config ------------------------------------------------------------------
# Read straight from the file so we don't depend on shell env being exported.
_env = dotenv_values(BACKEND_DIR / ".env")
CV_BASE_URL = (_env.get("CV_BASE_URL") or "").rstrip("/")
CV_API_TOKEN = _env.get("CV_API_TOKEN") or ""

if not CV_BASE_URL or not CV_API_TOKEN:
    sys.exit("ERROR: CV_BASE_URL and/or CV_API_TOKEN missing from cv-alerts-backend/.env")


def make_client(header_name: str) -> httpx.Client:
    """The ONLY place TLS verification is disabled.

    verify=False is EXERCISE-ONLY: the Cyber Vision Center is served over HTTPS on a
    raw IP with a self-signed certificate. Never ship this in production.
    """
    return httpx.Client(
        base_url=CV_BASE_URL,
        headers={header_name: CV_API_TOKEN, "Accept": "application/json"},
        verify=False,  # exercise-only: self-signed cert on raw IP
        timeout=20.0,
    )


def safe_status(client: httpx.Client, path: str, params: dict | None = None) -> tuple[int | None, Any]:
    """GET a path. Return (status_code, parsed_body_or_text). Never raises on HTTP errors."""
    try:
        r = client.get(path, params=params)
    except httpx.HTTPError as exc:
        return None, f"<transport error: {type(exc).__name__}>"
    try:
        return r.status_code, r.json()
    except (json.JSONDecodeError, ValueError):
        return r.status_code, r.text[:300]


def trim(body: Any, n: int = 3) -> Any:
    """Keep a small but representative slice of a response for sampling."""
    if isinstance(body, list):
        return body[:n]
    if isinstance(body, dict):
        out: dict[str, Any] = {}
        for k, v in body.items():
            if isinstance(v, list):
                out[k] = v[:n]
                out[f"__{k}_total_in_response__"] = len(v)
            else:
                out[k] = v
        return out
    return body


def count_items(body: Any) -> int | str:
    if isinstance(body, list):
        return len(body)
    if isinstance(body, dict):
        for k in ("results", "data", "items", "components", "flows", "events"):
            if isinstance(body.get(k), list):
                return len(body[k])
        return "dict (no obvious list field)"
    return "n/a"


# --- Step 1: confirm auth header + API version path --------------------------
# The skill says the header is "likely x-token-id" and the version "commonly /api/3.0"
# but tells us to VERIFY. So we try a small matrix of header names x version prefixes
# against a cheap endpoint and see what returns 2xx.
HEADER_CANDIDATES = ["x-token-id", "X-Token-Id", "x-api-key", "Authorization"]
VERSION_CANDIDATES = ["/api/3.0", "/api/3.1", "/api/1.0", "/api/2.0"]
# Probe endpoints that are usually cheap/always-present.
PROBE_ENDPOINTS = ["/version", "/ping", "/presets", "/components"]


def confirm_auth() -> tuple[str, str]:
    print("=" * 70)
    print("STEP 1: Confirm auth header + API version path")
    print(f"  Base URL: {CV_BASE_URL}  (token loaded, hidden)")
    print("=" * 70)
    for header in HEADER_CANDIDATES:
        # Authorization needs a Bearer prefix; handle that specially.
        token_header = header
        with httpx.Client(
            base_url=CV_BASE_URL,
            headers={
                header: (f"Bearer {CV_API_TOKEN}" if header == "Authorization" else CV_API_TOKEN),
                "Accept": "application/json",
            },
            verify=False,  # exercise-only
            timeout=20.0,
        ) as client:
            for version in VERSION_CANDIDATES:
                for ep in PROBE_ENDPOINTS:
                    path = f"{version}{ep}"
                    status, _ = safe_status(client, path)
                    flag = "OK " if status and 200 <= status < 300 else "   "
                    if status and status not in (404,):
                        print(f"  [{flag}] header={header:<15} {path:<22} -> {status}")
                    if status and 200 <= status < 300:
                        print(f"\n  >>> WORKING: header '{header}' + version '{version}'")
                        return header, version
    sys.exit("\nERROR: No header/version combination authenticated. Check token / docs.")


# --- Step 2: probe the endpoints that matter for alerts + comms graph --------
# name -> list of candidate paths (relative to the confirmed version prefix)
TARGETS: dict[str, list[str]] = {
    "components": ["/components", "/devices", "/assets"],
    "flows": ["/flows", "/activities", "/conversations"],
    "vulnerabilities": ["/vulnerabilities"],
    "events": ["/events"],
    "presets": ["/presets"],
    "groups": ["/groups"],
    "tags": ["/tags"],
    "sensors": ["/sensors"],
}


def probe_targets(header: str, version: str) -> dict[str, dict]:
    print("\n" + "=" * 70)
    print("STEP 2: Probe data endpoints (saving trimmed samples)")
    print("=" * 70)
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    summary: dict[str, dict] = {}
    token_value = f"Bearer {CV_API_TOKEN}" if header == "Authorization" else CV_API_TOKEN
    with httpx.Client(
        base_url=CV_BASE_URL,
        headers={header: token_value, "Accept": "application/json"},
        verify=False,  # exercise-only
        timeout=30.0,
    ) as client:
        for name, candidates in TARGETS.items():
            found = False
            for rel in candidates:
                path = f"{version}{rel}"
                # Ask for a small page where the API supports it; harmless if ignored.
                status, body = safe_status(client, path, params={"page": 1, "size": 5})
                if status and 200 <= status < 300:
                    n = count_items(body)
                    print(f"  [OK ] {name:<16} {path:<22} -> {status}  items={n}")
                    sample_path = SAMPLES_DIR / f"{name}.json"
                    sample_path.write_text(
                        json.dumps(
                            {"_endpoint": path, "_item_count_in_sample": n, "sample": trim(body)},
                            indent=2,
                        ),
                        encoding="utf-8",
                    )
                    summary[name] = {"path": path, "status": status, "count": n}
                    found = True
                    break
                else:
                    print(f"  [   ] {name:<16} {path:<22} -> {status}")
            if not found:
                summary[name] = {"path": None, "status": "not found", "count": 0}
    return summary


def main() -> None:
    header, version = confirm_auth()
    summary = probe_targets(header, version)
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Auth header : {header}")
    print(f"  API version : {version}")
    for name, info in summary.items():
        print(f"  {name:<16} -> {info}")
    print(f"\n  Samples written to: {SAMPLES_DIR}")


if __name__ == "__main__":
    main()
