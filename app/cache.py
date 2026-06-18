"""
Tiny single-value TTL cache.

The Cyber Vision Center is slow and occasionally returns 503 (see docs/API-FINDINGS.md), so we
must NOT call it on every browser request. One computed "bundle" (inventory + activities +
alerts) is cached for `ttl` seconds and shared by all endpoints. Thread-safe for the typical
uvicorn worker (a lock guards the recompute).
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Generic, TypeVar

T = TypeVar("T")


class TTLCache(Generic[T]):
    def __init__(self, ttl_seconds: float):
        self.ttl = ttl_seconds
        self._value: T | None = None
        self._expires_at: float = 0.0
        self._lock = threading.Lock()

    def get(self, compute: Callable[[], T], *, force: bool = False) -> T:
        now = time.monotonic()
        if not force and self._value is not None and now < self._expires_at:
            return self._value
        with self._lock:
            now = time.monotonic()
            if force or self._value is None or now >= self._expires_at:
                self._value = compute()
                self._expires_at = time.monotonic() + self.ttl
            return self._value

    def clear(self) -> None:
        with self._lock:
            self._value = None
            self._expires_at = 0.0
