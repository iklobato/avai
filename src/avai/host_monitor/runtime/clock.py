"""Injectable clock.

Anything that stamps a timestamp depends on a :class:`Clock` rather than
calling ``datetime.now`` directly, so tests can inject a
:class:`FrozenClock` and assert on deterministic output.
"""

from __future__ import annotations

from datetime import datetime, timezone


class Clock:
    """Wall-clock source. Production default."""

    def now_iso(self) -> str:
        """Current UTC instant as a second-resolution ISO-8601 string."""
        return datetime.now(timezone.utc).isoformat(timespec="seconds")


class FrozenClock(Clock):
    """A clock that always returns the same instant — for tests."""

    def __init__(self, iso: str) -> None:
        self._iso = iso

    def now_iso(self) -> str:
        return self._iso
