"""A small, thread-safe cache whose entries expire after a fixed time."""

from __future__ import annotations

import threading
from collections.abc import Hashable
from dataclasses import dataclass
from typing import Any

from avai.host_monitor.runtime import Clock


@dataclass(frozen=True)
class TtlPolicy:
    ttl_s: float
    max_entries: int


class TtlCache:
    """Entries live ``ttl_s`` seconds on the injected clock. A full cache is
    emptied rather than grown, so its size stays bounded without tracking
    use order. One instance per owner: nothing is shared through the class."""

    def __init__(self, clock: Clock, policy: TtlPolicy, lock: threading.Lock) -> None:
        self._clock = clock
        self._policy = policy
        self._lock = lock
        self._entries: dict[Hashable, tuple[float, Any]] = {}

    def get(self, key: Hashable) -> Any | None:
        with self._lock:
            hit = self._entries.get(key)
        if hit is None or self._clock.monotonic() - hit[0] >= self._policy.ttl_s:
            return None
        return hit[1]

    def put(self, key: Hashable, value: Any) -> None:
        with self._lock:
            if len(self._entries) >= self._policy.max_entries:
                self._entries.clear()
            self._entries[key] = (self._clock.monotonic(), value)
