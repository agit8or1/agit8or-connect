"""Replay / idempotency store interface.

`add(namespace, key, expires_at)` records a one-time value and returns True
the first time, False if it was already recorded and has not expired. Hosts
implement it on a table with a UNIQUE(namespace, key) constraint so that two
workers racing on the same value cannot both win (for example a database
table with a UNIQUE (namespace, key) constraint, or an INSERT ON CONFLICT
pattern). Record only AFTER the signature verified, so unauthenticated
callers cannot fill the table.

Implementations: MemoryReplayStore (one process) and storage.SqlReplayStore (SQLite / PostgreSQL,
multi-process, survives restarts). A store that cannot record MUST raise (fail closed), never answer True.

Namespaces used by the protocol: "assertion" (client assertion jti),
"dpop" (DPoP proof jti), "event" (webhook event id), "pairing" (pairing
request jti), "poll" (pairing status proof jti).
"""
from __future__ import annotations

import threading
import time
from typing import Dict, Protocol, Tuple


class ReplayStore(Protocol):
    def add(self, namespace: str, key: str, expires_at: int) -> bool: ...


class MemoryReplayStore:
    """Single process only (tests, development, the reference peer): forgets everything on restart and is
    not shared between workers. Production hosts use storage.SqlReplayStore (or an equivalent with a
    database-enforced unique key)."""

    def __init__(self, clock=time.time, max_entries: int = 100000):
        self._seen: Dict[Tuple[str, str], int] = {}
        self._lock = threading.Lock()
        self._clock = clock
        self._last_sweep = 0.0
        self.max_entries = max_entries

    def add(self, namespace: str, key: str, expires_at: int) -> bool:
        now = self._clock()
        with self._lock:
            if now - self._last_sweep > 60 or len(self._seen) > self.max_entries:
                self._seen = {k: v for k, v in self._seen.items() if v > now}
                self._last_sweep = now
                if len(self._seen) > self.max_entries:
                    from .errors import ConnectError
                    raise ConnectError('replay_store_unavailable', 'replay store full', 503)
            k = (namespace, key)
            if k in self._seen and self._seen[k] > now:
                return False
            self._seen[k] = int(expires_at)
            return True
