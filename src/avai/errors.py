"""The base of every error avai raises on purpose.

Own errors subclass :class:`AvaiError`. Errors that callers already catch as
a stdlib type (``RuntimeError``) keep that type as a second base, so existing
``except RuntimeError`` handlers still see them.
"""

from __future__ import annotations


class AvaiError(Exception):
    """Something avai detected and raised itself, not a library or a bug."""


class UnsupportedPlatformError(AvaiError, RuntimeError):
    """avai has no implementation for this operating system."""

    def __init__(self, system: str) -> None:
        self.system = system

    def __str__(self) -> str:
        return f"avai has no host implementation for platform: {self.system!r}"
