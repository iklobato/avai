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
from typing import Any, Iterable, Optional


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
