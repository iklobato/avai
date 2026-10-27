from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Iterable
from typing import Any, NamedTuple

from avai.errors import AvaiError

# Per-method default timeouts (seconds); they match the historical
# free-function defaults so behaviour is unchanged across the migration.
JSON_TIMEOUT_S = 60
NDJSON_TIMEOUT_S = 180
QUICK_TIMEOUT_S = 10
STDERR_EXCERPT_CHARS = 200


class CommandFailedError(AvaiError, RuntimeError):
    """A command exited non-zero; the message carries a stderr excerpt."""


class CommandOutput(NamedTuple):
    stdout: str
    stderr: str
    timed_out: bool


class CommandRunner:
    """Run external commands and decode their output."""

    def exists(self, name: str) -> bool:
        """True if *name* resolves on ``PATH`` (``shutil.which``)."""
        return shutil.which(name) is not None

    def json(self, cmd: list[str], timeout: int = JSON_TIMEOUT_S) -> Any:
        """Run *cmd* and parse stdout as a single JSON document.

        Raises ``CommandFailedError`` on a timeout or a non-zero exit (carrying a stderr
        excerpt). Returns ``None`` when stdout is empty.
        """
        completed = self._checked(cmd, timeout)
        return json.loads(completed.stdout) if completed.stdout else None

    def ndjson(
        self, cmd: list[str], timeout: int = NDJSON_TIMEOUT_S
    ) -> Iterable[dict[str, Any]]:
        """Run *cmd* and yield one parsed object per non-blank stdout line.

        Malformed lines are skipped. Raises ``CommandFailedError`` on a
        non-zero exit.
        """
        completed = self._checked(cmd, timeout)
        for line in completed.stdout.splitlines():
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

    def exit_code(self, cmd: list[str], timeout: int = QUICK_TIMEOUT_S) -> int | None:
        """Return *cmd*'s exit code, or ``None`` if it can't be run
        (missing binary, timeout). Never raises for those cases."""
        try:
            completed = subprocess.run(
                cmd, capture_output=True, timeout=timeout, check=False
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        return completed.returncode

    def text(self, cmd: list[str], timeout: int = QUICK_TIMEOUT_S) -> str:
        """Return *cmd*'s stdout as text, or ``""`` on a non-zero exit,
        missing binary, or timeout. For tools queried for their textual
        output (e.g. ``dscl``) where failure should degrade quietly."""
        try:
            completed = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return ""
        return (completed.stdout or "") if completed.returncode == 0 else ""

    def capture(self, cmd: list[str], timeout: int) -> CommandOutput:
        """Run *cmd* and return its stdout and stderr as text, whatever the
        exit code. On timeout the output produced so far is kept and
        ``timed_out`` is set: a capture tool such as tcpdump stops at the
        time cap on a quiet link and its partial output is still the
        answer. A missing binary raises ``FileNotFoundError``."""
        try:
            completed = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired as exc:
            return CommandOutput(
                self._as_text(exc.stdout), self._as_text(exc.stderr), True
            )
        return CommandOutput(completed.stdout or "", completed.stderr or "", False)

    def _checked(
        self, cmd: list[str], timeout: int
    ) -> subprocess.CompletedProcess[bytes]:
        try:
            completed = subprocess.run(
                cmd, capture_output=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise CommandFailedError(f"{cmd[0]} timed out after {timeout}s") from exc
        if completed.returncode != 0:
            stderr = completed.stderr.decode(errors="replace")
            raise CommandFailedError(
                f"{cmd[0]} rc={completed.returncode}: {stderr[:STDERR_EXCERPT_CHARS]}"
            )
        return completed

    def _as_text(self, partial: bytes | None) -> str:
        # TimeoutExpired carries bytes even when the run asked for text.
        if isinstance(partial, bytes):
            return partial.decode("utf-8", "replace")
        return partial or ""
