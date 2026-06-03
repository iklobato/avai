"""Injectable runtime collaborators.

These are the cohesive, stateful (or seam-bearing) objects that the rest
of the package depends on instead of reaching for module-level helper
functions: the single subprocess seam (:class:`CommandRunner`), the
injectable clock (:class:`Clock`), the hashing collaborator
(:class:`Digest`) and the external-SQLite reader
(:class:`ExternalSqliteReader`).

Collectors and per-OS adapters receive these via their constructors, so
tests can pass fakes (a ``CommandRunner`` returning canned tool output, a
``FrozenClock``) without spawning processes or depending on wall-clock
time.
"""

from __future__ import annotations

from .clock import Clock, FrozenClock
from .command_runner import CommandRunner
from .digest import Digest
from .sqlite_reader import ExternalSqliteReader

__all__ = [
    "Clock",
    "FrozenClock",
    "CommandRunner",
    "Digest",
    "ExternalSqliteReader",
]
