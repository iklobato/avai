"""Generic host log capture: journald plus tailed plain-text files."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from .. import constants, slices
from ..runtime import (
    CommandRunner,
    HostPaths,
)
from .base import SnapshotCollector

# syslog severity number -> name (RFC 5424 / journald PRIORITY).
_SYSLOG_LEVELS = {
    "0": "emerg",
    "1": "alert",
    "2": "crit",
    "3": "err",
    "4": "warning",
    "5": "notice",
    "6": "info",
    "7": "debug",
}


# Conservative level sniff for plain-text lines that carry no structured
# priority — only the actionable severities, so most lines stay unlabelled
# rather than being noisily mis-tagged. Needles require a delimiter (space /
# colon / bracket) so a substring inside an identifier doesn't trip them:
# e.g. a dpkg line about ``libgpg-error-dev`` is NOT an error.
_TEXT_LEVEL_PATTERNS = (
    ("crit", ("critical", "fatal", "panic", "[crit")),
    ("err", (" error", "error:", "[error", "[err]", " err ", " failed", "failure")),
    ("warning", (" warning", "warning:", "[warn", " warn ")),
)


def _journal_us_to_iso(value) -> Optional[str]:
    """journald ``__REALTIME_TIMESTAMP`` (microseconds since epoch) → ISO-8601
    UTC string, or None if it can't be parsed."""
    try:
        seconds = int(value) / 1_000_000
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat(
        timespec="seconds"
    )


def _sniff_text_level(line: str) -> Optional[str]:
    low = line.lower()
    for level, needles in _TEXT_LEVEL_PATTERNS:
        if any(n in low for n in needles):
            return level
    return None


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

    slice = slices.LOG_ENTRIES
    judge_enabled = False

    MAX_JOURNAL_LINES = 500
    MAX_FILE_LINES = 200
    _TAIL_BYTES = 64 * 1024
    _JOURNAL_TIMEOUT_S = 20

    # Plain-text logs worth surfacing that don't flow to journald. Missing or
    # unreadable paths are skipped silently — they vary by host.
    _DEFAULT_FILES = (
        "/var/log/dpkg.log",
        "/var/log/qualys/qualys-cep.log",
        "/var/log/falcon-libbpf.log",
    )

    def __init__(
        self,
        judge_hints: str = "",
        files: Optional[list[str]] = None,
        runner: Optional[CommandRunner] = None,
    ):
        super().__init__(judge_hints)
        self._runner = runner or CommandRunner()
        self._files = list(self._DEFAULT_FILES if files is None else files)

    def collect(self):
        yield from self._journald()
        for path_str in self._files:
            yield from self._tail_file(path_str)

    def _journald(self):
        if not self._runner.exists("journalctl"):
            return
        cmd = [
            "journalctl",
            "-o",
            "json",
            "--no-pager",
            "-n",
            str(self.MAX_JOURNAL_LINES),
        ]
        host_journal = HostPaths.translate("/var/log/journal")
        if constants.HOST_PREFIX and host_journal.is_dir():
            cmd.extend(["--directory", str(host_journal)])
        try:
            result = self._runner.capture(cmd, timeout=self._JOURNAL_TIMEOUT_S)
        except OSError as exc:
            constants.LOG.warning("journalctl read failed: %s", exc)
            return
        if result.timed_out:
            constants.LOG.warning(
                "journalctl read failed: timed out after %ss", self._JOURNAL_TIMEOUT_S
            )
            return
        for line in result.stdout.splitlines():
            row = self._parse_journal(line)
            if row is not None:
                yield row

    @staticmethod
    def _parse_journal(line: str) -> Optional[dict]:
        try:
            obj = json.loads(line)
        except (TypeError, ValueError):
            return None
        message = obj.get("MESSAGE")
        if isinstance(message, list):
            # journald encodes a non-UTF-8 message as an array of byte values.
            message = bytes(b & 0xFF for b in message).decode("utf-8", "replace")
        pid = obj.get("_PID")
        try:
            pid = int(pid) if pid is not None else None
        except (TypeError, ValueError):
            pid = None
        return {
            "source": "journald",
            "unit": obj.get("_SYSTEMD_UNIT")
            or obj.get("SYSLOG_IDENTIFIER")
            or obj.get("_COMM"),
            "level": _SYSLOG_LEVELS.get(str(obj.get("PRIORITY"))),
            "event_timestamp": _journal_us_to_iso(obj.get("__REALTIME_TIMESTAMP")),
            "pid": pid,
            "message": (message or "").strip() or None,
        }

    def _tail_file(self, path_str: str):
        path = HostPaths.translate(path_str)
        try:
            with open(path, "rb") as handle:
                handle.seek(0, 2)
                size = handle.tell()
                handle.seek(max(0, size - self._TAIL_BYTES))
                chunk = handle.read()
        except OSError:
            return  # missing / unreadable — expected, varies by host
        lines = [
            ln for ln in chunk.decode("utf-8", "replace").splitlines() if ln.strip()
        ]
        # A seek into the middle of the file leaves a partial first line.
        if size > self._TAIL_BYTES and lines:
            lines = lines[1:]
        unit = path.name
        for line in lines[-self.MAX_FILE_LINES :]:
            stripped = line.strip()
            yield {
                "source": str(path),
                "unit": unit,
                "level": _sniff_text_level(stripped),
                "event_timestamp": None,
                "pid": None,
                "message": stripped,
            }
