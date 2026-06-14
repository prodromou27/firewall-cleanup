"""In-process login throttle (brute-force mitigation).

Tracks recent failed login attempts keyed by (client_ip, email) in a sliding
time window. After too many failures the login endpoint returns HTTP 429 with a
Retry-After hint, slowing credential-stuffing and password-spraying without a
schema change.

Scope / caveats
---------------
- State lives in process memory: it resets on restart and is NOT shared across
  multiple worker processes. For a single-process deployment (the current
  default) this is effective. A multi-worker / multi-node deployment should back
  this with a shared store (e.g. Redis) — see _Throttle for the swap point.
- Keyed by ip + email so one attacker IP cannot lock out every account, and a
  distributed attack on one account is still bounded per source IP.
"""
from __future__ import annotations

import threading
import time
from typing import Dict, List, Tuple

# Tunables (kept module-level so tests/config can override).
MAX_FAILURES = 5            # failures allowed within the window before lockout
WINDOW_SECONDS = 15 * 60    # sliding window length
LOCKOUT_SECONDS = 15 * 60   # how long to keep rejecting once tripped


class _Throttle:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        # key -> list of failure timestamps (monotonic-ish wall clock)
        self._failures: Dict[Tuple[str, str], List[float]] = {}

    @staticmethod
    def _key(ip: str, email: str) -> Tuple[str, str]:
        return (ip or "unknown", (email or "").lower())

    def _prune(self, stamps: List[float], now: float) -> List[float]:
        cutoff = now - WINDOW_SECONDS
        return [t for t in stamps if t >= cutoff]

    def retry_after(self, ip: str, email: str) -> int:
        """Return seconds the caller must wait, or 0 if not currently locked."""
        now = time.time()
        with self._lock:
            stamps = self._prune(self._failures.get(self._key(ip, email), []), now)
            self._failures[self._key(ip, email)] = stamps
            if len(stamps) < MAX_FAILURES:
                return 0
            # Locked until LOCKOUT_SECONDS after the most recent failure.
            unlock_at = stamps[-1] + LOCKOUT_SECONDS
            return max(0, int(unlock_at - now))

    def record_failure(self, ip: str, email: str) -> None:
        now = time.time()
        with self._lock:
            key = self._key(ip, email)
            stamps = self._prune(self._failures.get(key, []), now)
            stamps.append(now)
            self._failures[key] = stamps

    def reset(self, ip: str, email: str) -> None:
        with self._lock:
            self._failures.pop(self._key(ip, email), None)


# Module-level singleton used by the auth router.
login_throttle = _Throttle()
