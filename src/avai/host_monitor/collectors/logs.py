from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import constants
from ..slices import Slices
from ..runtime import CommandRunner, HostPaths
from .base import SnapshotCollector

# syslog severity number -> name (RFC 5424 / journald PRIORITY).
SYSLOG_LEVELS = (
    ("0", "emerg"),
    ("1", "alert"),
    ("2", "crit"),
    ("3", "err"),
    ("4", "warning"),
    ("5", "notice"),
    ("6", "info"),
    ("7", "debug"),
)

# Conservative level sniff for plain-text lines that carry no structured
# priority — only the actionable severities, so most lines stay unlabelled
# rather than being noisily mis-tagged. Needles require a delimiter (space /
# colon / bracket) so a substring inside an identifier doesn't trip them:
# e.g. a dpkg line about ``libgpg-error-dev`` is NOT an error.
TEXT_LEVEL_PATTERNS = (
    ("crit", ("critical", "fatal", "panic", "[crit")),
    ("err", (" error", "error:", "[error", "[err]", " err ", " failed", "failure")),
    ("warning", (" warning", "warning:", "[warn", " warn ")),
)

MICROSECONDS_PER_SECOND = 1_000_000
BYTE_MASK = 0xFF
MAX_JOURNAL_LINES = 500
MAX_FILE_LINES = 200
TAIL_BYTES = 64 * 1024
JOURNAL_TIMEOUT_S = 20
# Plain-text logs worth surfacing that don't flow to journald. Missing or
# unreadable paths are skipped silently — they vary by host.
DEFAULT_LOG_FILES = (
    "/var/log/dpkg.log",
    "/var/log/qualys/qualys-cep.log",
    "/var/log/falcon-libbpf.log",
)


class TextLevel:
    """Severity sniffed from a plain-text log line, when it shows one."""

    def sniff(self, line: str) -> str | None:
        lowered = line.lower()
        return next(
            (
                level
                for level, needles in TEXT_LEVEL_PATTERNS
                if any(needle in lowered for needle in needles)
            ),
            None,
        )


class JournalLine:
    """One ``journalctl -o json`` line as a log_entries row."""

    def __init__(self, line: str) -> None:
        self._line = line

    def row(self) -> dict[str, Any] | None:
        try:
            event = json.loads(self._line)
        except (TypeError, ValueError):
            return None
        return {
            "source": "journald",
            "unit": event.get("_SYSTEMD_UNIT")
            or event.get("SYSLOG_IDENTIFIER")
            or event.get("_COMM"),
            "level": dict(SYSLOG_LEVELS).get(str(event.get("PRIORITY"))),
            "event_timestamp": self._timestamp(event.get("__REALTIME_TIMESTAMP")),
            "pid": self._pid(event.get("_PID")),
            "message": (self._message(event.get("MESSAGE")) or "").strip() or None,
        }

    def _message(self, message: Any) -> str | None:
        if isinstance(message, list):
            # journald encodes a non-UTF-8 message as an array of byte values.
            return bytes(byte & BYTE_MASK for byte in message).decode(
                "utf-8", "replace"
            )
        return message

    def _pid(self, raw: Any) -> int | None:
        try:
            return int(raw) if raw is not None else None
        except (TypeError, ValueError):
            return None

    def _timestamp(self, raw: Any) -> str | None:
        """journald ``__REALTIME_TIMESTAMP`` (microseconds since epoch) →
        ISO-8601 UTC string, or None if it can't be parsed."""
        try:
            seconds = int(raw) / MICROSECONDS_PER_SECOND
        except (TypeError, ValueError):
            return None
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat(
            timespec="seconds"
        )


class JournalReader:
    """The newest journald entries, read through ``journalctl``."""

    def __init__(self, runner: CommandRunner, logger: logging.Logger) -> None:
        self._runner = runner
        self._logger = logger

    def rows(self) -> Iterator[dict[str, Any]]:
        if not self._runner.exists("journalctl"):
            return
        try:
            output = self._runner.capture(self._command(), timeout=JOURNAL_TIMEOUT_S)
        except OSError as exc:
            self._logger.warning("journalctl read failed: %s", exc)
            return
        if output.timed_out:
            self._logger.warning(
                "journalctl read failed: timed out after %ss", JOURNAL_TIMEOUT_S
            )
            return
        parsed = (JournalLine(line).row() for line in output.stdout.splitlines())
        yield from (row for row in parsed if row is not None)

    def _command(self) -> list[str]:
        cmd = ["journalctl", "-o", "json", "--no-pager", "-n", str(MAX_JOURNAL_LINES)]
        host_journal = HostPaths().translate("/var/log/journal")
        if constants.HOST_PREFIX and host_journal.is_dir():
            cmd.extend(["--directory", str(host_journal)])
        return cmd


class LogFileTail:
    """The last lines of one plain-text log file."""

    def __init__(self, path: Path) -> None:
        self._path = path

    @classmethod
    def on_host(cls, path_str: str) -> LogFileTail:
        return cls(HostPaths().translate(path_str))

    def rows(self) -> Iterator[dict[str, Any]]:
        tail = self._tail()
        if tail is None:
            return  # missing / unreadable — expected, varies by host
        for line in tail[-MAX_FILE_LINES:]:
            stripped = line.strip()
            yield {
                "source": str(self._path),
                "unit": self._path.name,
                "level": TextLevel().sniff(stripped),
                "event_timestamp": None,
                "pid": None,
                "message": stripped,
            }

    def _tail(self) -> list[str] | None:
        try:
            with open(self._path, "rb") as handle:
                size = handle.seek(0, os.SEEK_END)
                handle.seek(max(0, size - TAIL_BYTES))
                chunk = handle.read()
        except OSError:
            return None
        lines = [
            line
            for line in chunk.decode("utf-8", "replace").splitlines()
            if line.strip()
        ]
        # A seek into the middle of the file leaves a partial first line.
        return lines[1:] if size > TAIL_BYTES and lines else lines


class LogTailCollector(SnapshotCollector):
    """Generic host log capture: a per-cycle snapshot of the most recent log
    lines from journald (the systemd journal already aggregates syslog, the
    kernel, sshd, and most services) plus a configured set of plain-text log
    files that don't reach journald (vendor agents, dpkg, …).

    Bulk telemetry: ``judge_enabled`` is False — the dashboard's logs panel
    paginates / filters / searches these; they aren't individually LLM-judged.
    Bounded every cycle (newest N journald entries, last N lines per file) and
    shown for the latest run only, like the other snapshot collectors.
    """

    slice = Slices.LOG_ENTRIES
    judge_enabled = False

    def __init__(
        self, judge_hints: str, journal: JournalReader, files: tuple[str, ...]
    ) -> None:
        super().__init__(judge_hints)
        self._journal = journal
        self._files = files

    @classmethod
    def create(
        cls, judge_hints: str, runner: CommandRunner, logger: logging.Logger
    ) -> LogTailCollector:
        return cls(judge_hints, JournalReader(runner, logger), DEFAULT_LOG_FILES)

    def collect(self) -> Iterator[dict[str, Any]]:
        yield from self._journal.rows()
        for path_str in self._files:
            yield from LogFileTail.on_host(path_str).rows()
