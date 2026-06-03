"""Host-state probes: network connections and service liveness."""

from __future__ import annotations

import sys
from typing import Optional

try:
    import psutil
except ImportError:
    sys.stderr.write("Required: pip install psutil\n")
    sys.exit(2)

from .command_runner import CommandRunner


class PsutilConnections:
    """Thin safety wrapper over psutil's connection table."""

    @staticmethod
    def inet() -> list:
        """All INET connections, translating psutil's AccessDenied into a
        PermissionError with an actionable message (it needs root for full
        visibility)."""
        try:
            return psutil.net_connections(kind="inet")
        except psutil.AccessDenied as e:
            raise PermissionError(
                "psutil.net_connections requires root for full visibility"
            ) from e


class ServiceProbe:
    """POSIX service-liveness checks via the injected CommandRunner."""

    def __init__(self, runner: Optional[CommandRunner] = None) -> None:
        self._runner = runner or CommandRunner()

    def loaded(self, label: str) -> Optional[int]:
        """1 if a launchd service *label* is loaded, 0 if not, None on
        error (``launchctl list <label>`` exit code)."""
        code = self._runner.exit_code(["launchctl", "list", label])
        return None if code is None else int(code == 0)

    def running(self, name: str) -> Optional[int]:
        """1 if a process named *name* is running, 0 if not, None on error.

        Uses ``pgrep -x`` (exact match) so it catches system-domain
        services (sshd, screensharingd, ARDAgent) that ``launchctl list``
        misses from the user session."""
        code = self._runner.exit_code(["pgrep", "-x", name])
        return None if code is None else int(code == 0)
