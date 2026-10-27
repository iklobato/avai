from __future__ import annotations

import logging
from dataclasses import dataclass
from collections.abc import Iterable, Iterator
from typing import Any, Protocol

import psutil

from .command_runner import CommandRunner
from .host_paths import HostPaths
from .mounts import HostPart, HostRootfs, HostUsage

SIGNAL_ON = 1
SIGNAL_OFF = 0
ROOTFS_DIR = "rootfs"


@dataclass(frozen=True)
class OwnedSocket:
    """One entry of a process's own socket table plus that process's pid,
    read the same way as an entry of the system-wide table."""

    pid: int
    entry: Any

    @property
    def family(self) -> Any:
        return self.entry.family

    @property
    def type(self) -> Any:
        return self.entry.type

    @property
    def laddr(self) -> Any:
        return self.entry.laddr

    @property
    def raddr(self) -> Any:
        return self.entry.raddr

    @property
    def status(self) -> str:
        return self.entry.status


class PsutilConnections:
    """Thin safety wrapper over psutil's connection table."""

    def inet(self) -> list[Any]:
        """All INET connections, translating psutil's AccessDenied into a
        PermissionError with an actionable message (it needs root for full
        visibility)."""
        try:
            return psutil.net_connections(kind="inet")
        except psutil.AccessDenied as exc:
            raise PermissionError(
                "psutil.net_connections requires root for full visibility"
            ) from exc

    def visible(self) -> list[Any]:
        """Every INET connection this process can see. Without root (macOS
        denies the system-wide table) it reads each process's own table
        instead: the sockets of the processes this user may inspect. A
        partial view, so only for collectors; a yes/no answer must use
        :meth:`inet` and know when it cannot tell."""
        try:
            return self.inet()
        except PermissionError:
            return [
                socket
                for process in psutil.process_iter()
                for socket in self._own_sockets(process)
            ]

    def listening(self) -> list[Any]:
        """The visible INET sockets in LISTEN state."""
        return [conn for conn in self.visible() if conn.status == psutil.CONN_LISTEN]

    def _own_sockets(self, process: psutil.Process) -> list[OwnedSocket]:
        try:
            sockets = process.net_connections(kind="inet")
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return []
        return [OwnedSocket(process.pid, socket) for socket in sockets]

    def process_name(self, pid: int) -> str | None:
        """Name of the process *pid*, or None when it is gone or hidden."""
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None


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

    def virtual_memory(self) -> Any:
        return psutil.virtual_memory()

    def swap_memory(self) -> Any:
        return psutil.swap_memory()

    def cpu_sample(self, interval: float) -> list[Any]:
        """Per-core CPU times-percent over one blocking ``interval`` window.

        Returns a list of namedtuples (one per logical core) carrying
        ``user``/``system``/``idle``/… percentages. The collector derives
        the overall busy% and per-core busy% from this single window, so
        the breakdown and the per-core figures are internally consistent.
        """
        return psutil.cpu_times_percent(interval=interval, percpu=True)

    def load_average(self) -> tuple[float, float, float] | None:
        """``(1, 5, 15)``-minute load averages, or None where unsupported."""
        try:
            return psutil.getloadavg()
        except (AttributeError, OSError):
            return None

    def cpu_count(self) -> tuple[int | None, int | None]:
        """``(physical, logical)`` core counts."""
        return psutil.cpu_count(logical=False), psutil.cpu_count(logical=True)

    def boot_time(self) -> float:
        return psutil.boot_time()

    def task_counts(self) -> dict[str, int]:
        """``{total, running, threads}`` across all processes — htop's
        'Tasks: N, M thr, K running' line. One light ``process_iter``;
        processes that vanish mid-walk are skipped."""
        tasks = [proc.info for proc in psutil.process_iter(["status", "num_threads"])]
        return {
            "total": len(tasks),
            "running": sum(
                1 for task in tasks if task.get("status") == psutil.STATUS_RUNNING
            ),
            "threads": sum(task.get("num_threads") or 0 for task in tasks),
        }

    def process_table(self, attrs: list[str]) -> Iterator[dict[str, Any]]:
        """One ``attrs`` dict per process; a field psutil may not read
        comes back as None instead of dropping the process."""
        for proc in psutil.process_iter(attrs, ad_value=None):
            yield proc.info

    def net_if_addrs(self) -> dict[str, Any]:
        return psutil.net_if_addrs()

    def net_if_stats(self) -> dict[str, Any]:
        return psutil.net_if_stats()

    def net_io_counters(self) -> dict[str, Any]:
        """Per-interface I/O counters."""
        return psutil.net_io_counters(pernic=True)


class DiskMetrics:
    """Thin seam over psutil's filesystem + disk-I/O readings (the ``df``
    table htop and similar tools show). Mirrors :class:`PsutilConnections`:
    a missing/unreadable source degrades to an empty result rather than
    raising, since an unmountable pseudo-filesystem is normal.

    **Container mode.** psutil reads the *container's* mount table and
    statvfs's the *container's* paths, so a containerised monitor would
    report its own overlay + bind mounts as "host disks" — wrong and
    duplicated. When the host root is bind-mounted read-only at
    ``$HOST_PREFIX/rootfs`` (see docker-compose.yml), this reads the real
    host mount table and measures each filesystem through that prefix
    instead. In container mode *without* that mount we emit nothing (and
    log once) rather than present misleading container-internal rows.
    """

    def __init__(self, logger: logging.Logger, paths: HostPaths) -> None:
        self._logger = logger
        self._paths = paths

    def partitions(self) -> list[Any]:
        rootfs = self._rootfs()
        if rootfs is not None:
            return rootfs.partitions()
        if self._paths.in_container():
            # Container mode but the host root isn't mounted: psutil would
            # surface the container's overlay/bind mounts as host disks.
            # Skip rather than mislead.
            self._logger.warning(
                "disk_usage: container mode but %s is not mounted; "
                "skipping (bind-mount the host root read-only to enable)",
                self._paths.under_prefix(ROOTFS_DIR),
            )
            return []
        try:
            return psutil.disk_partitions(all=False)
        except OSError:
            return []

    def mount_table(self) -> list[HostPart]:
        """Every mount, pseudo-filesystems included (``proc``, ``tmpfs``,
        ``cgroup``...), or [] when the table can't be read."""
        try:
            return psutil.disk_partitions(all=True)
        except (psutil.AccessDenied, PermissionError):
            return []

    def usage(self, mountpoint: str) -> HostUsage:
        """Usage for one mountpoint. Raises (``PermissionError``/``OSError``)
        for an unreadable mount — the caller skips that partition. In
        container mode the mountpoint is a host path measured through the
        rootfs mount."""
        rootfs = self._rootfs()
        if rootfs is None:
            return psutil.disk_usage(mountpoint)
        return rootfs.usage(mountpoint)

    def io_counters(self) -> dict[str, Any]:
        # /proc/diskstats is not namespaced, so psutil already reports the
        # host's per-device counters even from inside the container.
        try:
            return psutil.disk_io_counters(perdisk=True) or {}
        except (OSError, RuntimeError):
            return {}

    def _rootfs(self) -> HostRootfs | None:
        if not self._paths.in_container():
            return None
        candidate = self._paths.under_prefix(ROOTFS_DIR)
        return HostRootfs(str(candidate)) if candidate.is_dir() else None


class TriState:
    """Tri-state OR over 1/0/None signals: 1 if any signal is on, else 0 if
    any signal is known-off, else None (all unknown). Lets a control combine
    an authoritative-but-maybe-unavailable signal with a fallback without a
    known-off masking an unknown-on."""

    def any_on(self, signals: Iterable[int | None]) -> int | None:
        known = [signal for signal in signals if signal is not None]
        if SIGNAL_ON in known:
            return SIGNAL_ON
        if SIGNAL_OFF in known:
            return SIGNAL_OFF
        return None


# --- capability seams: posture/behaviour of a service, one mechanism each ---
# These are the OS-specific strategies a NetworkServiceControl composes (DIP). The
# control depends on these tiny interfaces, never on the commands directly;
# the composition root (host module) injects the right implementation.


class ServiceSupervisor(Protocol):
    """Whether a managed service is *enabled* (configured to be reachable),
    independent of whether its process happens to be running right now."""

    def enabled(self, unit: str) -> int | None: ...


class PortInspector(Protocol):
    """Socket-level posture/behaviour: is something listening on a port
    (enabled/exposed), and is there a live peer (in use right now)."""

    def listening(self, port: int) -> int | None: ...
    def established(self, port: int) -> int | None: ...


class ProcessInspector(Protocol):
    """Whether a process with an exact name is running (behaviour signal)."""

    def running(self, name: str) -> int | None: ...


class LaunchdServiceSupervisor:
    """macOS: a system-domain launchd job is enabled when it's bootstrapped
    (``launchctl print system/<label>`` exits 0). Needs root, which the
    monitor has."""

    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner

    def enabled(self, unit: str) -> int | None:
        code = self._runner.exit_code(["launchctl", "print", f"system/{unit}"])
        return None if code is None else int(code == 0)


class SystemdServiceSupervisor:
    """Linux: ``systemctl is-enabled <unit>`` exits 0 for enabled/static."""

    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner

    def enabled(self, unit: str) -> int | None:
        code = self._runner.exit_code(["systemctl", "is-enabled", unit])
        return None if code is None else int(code == 0)


class PsutilPortInspector:
    """Cross-platform port posture/behaviour from the psutil connection table
    (one implementation for every OS). Needs root for full visibility — the
    monitor runs as root; without it both signals degrade to None."""

    def __init__(self, connections: PsutilConnections) -> None:
        self._connections = connections

    def listening(self, port: int) -> int | None:
        return self._count(port, psutil.CONN_LISTEN)

    def established(self, port: int) -> int | None:
        return self._count(port, psutil.CONN_ESTABLISHED)

    def _count(self, port: int, status: str) -> int | None:
        try:
            conns = self._connections.inet()
        except PermissionError:
            return None
        matched = any(
            getattr(getattr(conn, "laddr", None), "port", None) == port
            and conn.status == status
            for conn in conns
        )
        return int(matched)


class PsutilProcessInspector:
    """Cross-platform exact-name process check (one implementation for every
    OS); replaces the POSIX-only ``pgrep -x`` shell-out."""

    def running(self, name: str) -> int | None:
        try:
            return int(
                any(
                    proc.info.get("name") == name
                    for proc in psutil.process_iter(["name"])
                )
            )
        except psutil.Error:
            return None
