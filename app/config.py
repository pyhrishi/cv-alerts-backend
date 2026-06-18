"""Environment configuration. The token is read here and never logged."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parents[1]

# Load .env if present (local dev). On Render the vars come from the dashboard.
load_dotenv(BACKEND_DIR / ".env")


def _require(name: str) -> str:
    val = os.getenv(name, "").strip()
    if not val:
        raise RuntimeError(f"Missing required env var {name} (set it in .env or the host dashboard)")
    return val


def cv_base_url() -> str:
    return _require("CV_BASE_URL").rstrip("/")


def cv_api_token() -> str:
    # Returned only to the CV client; never printed or sent to the browser.
    return _require("CV_API_TOKEN")


def allowed_origins() -> list[str]:
    """Comma-separated CORS allowlist. Tight by default; NEVER '*' in the submission."""
    raw = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000")
    return [o.strip() for o in raw.split(",") if o.strip()]


def cache_ttl_seconds() -> float:
    return float(os.getenv("CACHE_TTL_SECONDS", "60"))


def data_mode() -> str:
    """'snapshot' (default) serves the bundled sample data and NEVER calls the Center — safe for a
    public demo URL. 'live' calls the Center (requires CV_BASE_URL + CV_API_TOKEN) and falls back
    to snapshot if it's unreachable. The data_source field in responses always reflects reality."""
    mode = os.getenv("DATA_MODE", "snapshot").strip().lower()
    return mode if mode in ("snapshot", "live") else "snapshot"

