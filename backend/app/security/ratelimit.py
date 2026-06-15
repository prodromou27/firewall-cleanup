"""In-process per-IP API rate limiter (sliding window).

A lightweight defense against scraping and abusive bursts, layered on top of the
auth-specific login throttle. State lives in process memory: it resets on
restart and is NOT shared across worker processes. For a single-process
deployment (the current default) this is effective; back it with a shared store
(e.g. Redis) for multi-worker / multi-node deployments — `_RateLimiter.allow`
is the swap point.
"""
from __future__ import annotations

import threading
import time
from typing import Deque, Dict
from collections import deque


class _RateLimiter:
    def __init__(self, max_per_minute: int) -> None:
        self.max_per_minute = max_per_minute
        self._window = 60.0
        self._lock = threading.Lock()
        self._hits: Dict[str, Deque[float]] = {}

    def allow(self, key: str) -> tuple[bool, int]:
        """Record a hit for `key`. Returns (allowed, retry_after_seconds)."""
        if self.max_per_minute <= 0:
            return True, 0
        now = time.time()
        cutoff = now - self._window
        with self._lock:
            dq = self._hits.get(key)
            if dq is None:
                dq = deque()
                self._hits[key] = dq
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.max_per_minute:
                # Caller must wait until the oldest hit ages out of the window.
                retry_after = max(1, int(dq[0] + self._window - now) + 1)
                return False, retry_after
            dq.append(now)
            return True, 0
