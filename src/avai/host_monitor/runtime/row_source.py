from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any, Protocol

from avai.errors import AvaiError

from .command_runner import CommandRunner

SNAPSHOT_TIMEOUT_S = 30


class MissingToolError(AvaiError, RuntimeError):
    """The command a snapshot needs is not installed on this host."""


class RowParser(Protocol):
    """Pure transform from a tool's/file's text output to row dicts."""

    def parse(self, text: str) -> list[dict[str, Any]]: ...


class RowSource(Protocol):
    """Yields the rows for one snapshot collector this cycle."""

    def rows(self) -> Iterable[dict[str, Any]]: ...


class CommandSnapshot:
    """Run a command once and parse its stdout into rows.

    Raises ``MissingToolError`` if the binary is absent (the Runner records
    it as a collector error, exactly like the tcpdump collectors) rather
    than silently yielding nothing — a missing tool is a visible gap, not a
    clean empty result.
    """

    def __init__(
        self, runner: CommandRunner, command: list[str], parser: RowParser
    ) -> None:
        self._runner = runner
        self._command = command
        self._parser = parser

    def rows(self) -> Iterable[dict[str, Any]]:
        if not self._runner.exists(self._command[0]):
            raise MissingToolError(f"{self._command[0]} not found on PATH")
        text = self._runner.text(self._command, timeout=SNAPSHOT_TIMEOUT_S)
        return self._parser.parse(text)


class FileSnapshot:
    """Read a file once and parse it into rows.

    A missing file yields no rows (an absent config — e.g. no
    ``~/.ssh/known_hosts`` — is normal, not an error).
    """

    def __init__(self, path: Path, parser: RowParser) -> None:
        self._path = path
        self._parser = parser

    def rows(self) -> Iterable[dict[str, Any]]:
        try:
            text = self._path.read_text(errors="replace")
        except (OSError, UnicodeDecodeError):
            return []
        return self._parser.parse(text)
