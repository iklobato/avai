"""Run-once row sources for snapshot collectors.

The snapshot twin of :mod:`stream_source`. Most host/network-state
collectors are "run a per-OS command (or read a per-OS file), parse the
text into rows" — the gather and the parser vary per OS, the contract
(the collector's model/judge_fields) does not.

:class:`CommandSnapshot` and :class:`FileSnapshot` own the gather +
error handling; a :class:`RowParser` strategy (pure ``text -> rows``,
injected per OS) owns the parsing and is unit-tested without a
subprocess. The collector depends only on the narrow :class:`RowSource`
port (ISP); the host bundles the OS-specific ``(command, parser)`` pair
as the composition root (DIP).
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Protocol

from .command_runner import CommandRunner


class RowParser(Protocol):
    """Pure transform from a tool's/file's text output to row dicts."""

    def parse(self, text: str) -> list[dict]: ...


class RowSource(Protocol):
    """Yields the rows for one snapshot collector this cycle."""

    def rows(self) -> Iterable[dict]: ...


class CommandSnapshot:
    """Run a command once and parse its stdout into rows.

    Raises ``RuntimeError`` if the binary is absent (the Runner records it
    as a collector error, exactly like the tcpdump collectors) rather than
    silently yielding nothing — a missing tool is a visible gap, not a
    clean empty result.
    """

    def __init__(
        self,
        runner: CommandRunner,
        command: list[str],
        parser: RowParser,
        *,
        timeout: int = 30,
    ) -> None:
        self._runner = runner
        self._command = command
        self._parser = parser
        self._timeout = timeout

    def rows(self) -> Iterable[dict]:
        if not self._runner.exists(self._command[0]):
            raise RuntimeError(f"{self._command[0]} not found on PATH")
        text = self._runner.text(self._command, timeout=self._timeout)
        return self._parser.parse(text)


class FileSnapshot:
    """Read a file once and parse it into rows.

    A missing file yields no rows (an absent config — e.g. no
    ``~/.ssh/known_hosts`` — is normal, not an error).
    """

    def __init__(self, path: Path, parser: RowParser) -> None:
        self._path = path
        self._parser = parser

    def rows(self) -> Iterable[dict]:
        try:
            text = self._path.read_text(errors="replace")
        except (OSError, UnicodeDecodeError):
            return []
        return self._parser.parse(text)
