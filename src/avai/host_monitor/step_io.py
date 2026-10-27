"""Guarded reads and writes against the sink for best-effort work."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TypeVar

from .failures import HOST_FAILURES
from .runtime import Clock
from .sink import Sink

Value = TypeVar("Value")


@dataclass(frozen=True)
class StepIO:
    """Where a step reads and writes, and where its failures are logged."""

    sink: Sink
    logger: logging.Logger
    clock: Clock = field(default_factory=Clock)

    def read(self, label: str, action: Callable[[], Value]) -> Value | None:
        try:
            return action()
        except HOST_FAILURES as exc:
            self.logger.warning("%s failed: %s", label, exc)
            return None

    def wrote(self, label: str, action: Callable[[], object]) -> bool:
        try:
            action()
        except HOST_FAILURES as exc:
            self.logger.warning("%s failed: %s", label, exc)
            return False
        return True

    def matches(self, action: Callable[[], object], expected: str) -> bool:
        """An optimisation check: a failed read means "not the same"."""
        try:
            return action() == expected
        except HOST_FAILURES:
            return False
