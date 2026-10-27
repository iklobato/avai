"""The short-lived cache the dashboard keeps for slow panel reads."""

from __future__ import annotations

import threading

from avai.dashboard.queries.ttl_cache import TtlCache, TtlPolicy
from avai.host_monitor.runtime import Clock


class _ManualClock(Clock):
    """A monotonic clock the test moves by hand."""

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds

    def monotonic(self) -> float:
        return self.seconds


class TestTtlCache:
    TTL_S = 15.0
    MAX_ENTRIES = 2
    START = 100.0
    JUST_BEFORE = 14.9

    def _cache(self, clock: Clock) -> TtlCache:
        return TtlCache(
            clock, TtlPolicy(self.TTL_S, self.MAX_ENTRIES), threading.Lock()
        )

    def test_a_value_is_served_until_its_ttl_runs_out(self) -> None:
        clock = _ManualClock(self.START)
        cache = self._cache(clock)
        cache.put("page", {"rows": [1]})

        clock.seconds = self.START + self.JUST_BEFORE
        fresh = cache.get("page")
        clock.seconds = self.START + self.TTL_S
        expired = cache.get("page")

        assert (fresh, expired) == ({"rows": [1]}, None)

    def test_a_full_cache_starts_over_instead_of_growing(self) -> None:
        cache = self._cache(_ManualClock(self.START))
        cache.put("a", "first")
        cache.put("b", "second")

        cache.put("c", "third")

        assert (cache.get("a"), cache.get("b"), cache.get("c")) == (
            None,
            None,
            "third",
        )

    def test_two_caches_do_not_share_entries(self) -> None:
        clock = _ManualClock(self.START)
        first, second = self._cache(clock), self._cache(clock)

        first.put("page", "rows")

        assert second.get("page") is None
