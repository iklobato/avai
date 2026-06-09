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


class SystemMetrics:
    """Thin seam over psutil's system-wide resource readings (memory, swap,
    CPU, load, uptime, task tallies) — the aggregate "meters" htop shows.

    Pure pass-throughs to psutil so the collector that shapes the row stays
    free of the ``psutil`` global and is faked structurally in tests (same
    discipline as :class:`PsutilConnections`). The one piece of mechanics
    kept here is the blocking CPU sample: ``cpu_times_percent`` with a real
    ``interval`` is the only call that returns a meaningful reading on its
    *first* invocation (``interval=None`` returns 0.0 / since-import noise),
    so the timing concern lives in one place rather than in the collector.
    """

    def virtual_memory(self):
        return psutil.virtual_memory()

    def swap_memory(self):
        return psutil.swap_memory()

    def cpu_sample(self, interval: float) -> list:
        """Per-core CPU times-percent over one blocking ``interval`` window.

        Returns a list of namedtuples (one per logical core) carrying
        ``user``/``system``/``idle``/… percentages. The collector derives
        the overall busy% and per-core busy% from this single window, so
        the breakdown and the per-core figures are internally consistent.
        """
        return psutil.cpu_times_percent(interval=interval, percpu=True)

    def load_average(self) -> Optional[tuple]:
        """``(1, 5, 15)``-minute load averages, or None where unsupported."""
        try:
            return psutil.getloadavg()
        except (AttributeError, OSError):
            return None

    def cpu_count(self) -> tuple[Optional[int], Optional[int]]:
        """``(physical, logical)`` core counts."""
        return psutil.cpu_count(logical=False), psutil.cpu_count(logical=True)

    def boot_time(self) -> float:
        return psutil.boot_time()

    def task_counts(self) -> dict:
        """``{total, running, threads}`` across all processes — htop's
        'Tasks: N, M thr, K running' line. One light ``process_iter``;
        processes that vanish mid-walk are skipped."""
        total = running = threads = 0
        for p in psutil.process_iter(["status", "num_threads"]):
            total += 1
            info = p.info
            if info.get("status") == psutil.STATUS_RUNNING:
                running += 1
            threads += info.get("num_threads") or 0
        return {"total": total, "running": running, "threads": threads}


class DiskMetrics:
    """Thin seam over psutil's filesystem + disk-I/O readings (the ``df``
    table htop and similar tools show). Mirrors :class:`PsutilConnections`:
    a missing/unreadable source degrades to an empty result rather than
    raising, since an unmountable pseudo-filesystem is normal."""

    def partitions(self) -> list:
        try:
            return psutil.disk_partitions(all=False)
        except OSError:
            return []

    def usage(self, mountpoint: str):
        """Usage for one mountpoint. Raises (``PermissionError``/``OSError``)
        for an unreadable mount — the caller skips that partition."""
        return psutil.disk_usage(mountpoint)

    def io_counters(self) -> dict:
        try:
            return psutil.disk_io_counters(perdisk=True) or {}
        except (OSError, RuntimeError):
            return {}


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
