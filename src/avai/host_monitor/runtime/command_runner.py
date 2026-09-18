"""The single subprocess seam.

Every native-tool invocation in the package goes through a
:class:`CommandRunner` instance. Collectors and per-OS adapters never
import :mod:`subprocess` directly; they receive a runner and call it. A
test injects a fake runner that returns canned tool output, so a parser
can be exercised with no process spawned and no OS dependency.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any, Iterable, NamedTuple, Optional


class CommandOutput(NamedTuple):
    stdout: str
    stderr: str
    timed_out: bool


class CommandRunner:
    """Run external commands and decode their output.

    The per-method default timeouts match the historical free-function
    defaults so behaviour is unchanged across the migration.
    """

    def exists(self, name: str) -> bool:
        """True if *name* resolves on ``PATH`` (``shutil.which``)."""
        return shutil.which(name) is not None

    def json(self, cmd: list[str], timeout: int = 60) -> Any:
        """Run *cmd* and parse stdout as a single JSON document.

        Raises ``RuntimeError`` on a non-zero exit (carrying a stderr
        excerpt). Returns ``None`` when stdout is empty.
        """
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
        if r.returncode != 0:
            raise RuntimeError(
                f"{cmd[0]} rc={r.returncode}: "
                f"{r.stderr.decode(errors='replace')[:200]}"
            )
        return json.loads(r.stdout) if r.stdout else None

    def ndjson(self, cmd: list[str], timeout: int = 180) -> Iterable[dict]:
        """Run *cmd* and yield one parsed object per non-blank stdout line.

        Malformed lines are skipped. Raises ``RuntimeError`` on a non-zero
        exit.
        """
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
        if r.returncode != 0:
            raise RuntimeError(
                f"{cmd[0]} rc={r.returncode}: "
                f"{r.stderr.decode(errors='replace')[:200]}"
            )
        for line in r.stdout.splitlines():
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

    def exit_code(self, cmd: list[str], timeout: int = 10) -> Optional[int]:
        """Return *cmd*'s exit code, or ``None`` if it can't be run
        (missing binary, timeout). Never raises for those cases."""
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
            return r.returncode
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def text(self, cmd: list[str], timeout: int = 10) -> str:
        """Return *cmd*'s stdout as text, or ``""`` on a non-zero exit,
        missing binary, or timeout. For tools queried for their textual
        output (e.g. ``dscl``) where failure should degrade quietly."""
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False
            )
            return (r.stdout or "") if r.returncode == 0 else ""
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return ""

    def capture(self, cmd: list[str], timeout: int) -> CommandOutput:
        """Run *cmd* and return its stdout and stderr as text, whatever the
        exit code. On timeout the output produced so far is kept and
        ``timed_out`` is set: a capture tool such as tcpdump stops at the
        time cap on a quiet link and its partial output is still the
        answer. A missing binary raises ``FileNotFoundError``."""
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired as e:
            return CommandOutput(_as_text(e.stdout), _as_text(e.stderr), True)
        return CommandOutput(r.stdout or "", r.stderr or "", False)


def _as_text(partial) -> str:
    # TimeoutExpired carries bytes even when the run asked for text.
    if isinstance(partial, bytes):
        return partial.decode("utf-8", "replace")
    return partial or ""
