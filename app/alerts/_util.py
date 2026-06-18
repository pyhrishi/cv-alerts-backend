"""Small shared helpers for the alert detectors (no network, no state)."""
from __future__ import annotations

from datetime import datetime, timezone


def ms_to_iso(ms: int | None) -> str | None:
    """Epoch milliseconds -> ISO8601 UTC string. CV timestamps are epoch-ms."""
    if ms is None:
        return None
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat().replace("+00:00", "Z")
