"""Host-state probes: network connections and service liveness."""

from __future__ import annotations

import os
import sys
from collections import namedtuple
from typing import Optional

try:
    import psutil
except ImportError:
    sys.stderr.write("Required: pip install psutil\n")
    sys.exit(2)

from .. import constants
from .command_runner import CommandRunner

# Virtual / pseudo filesystems that carry no meaningful capacity — never
# part of a "df" view, and the bulk of what a container's own mount table
# is made of. Used to filter the host mount table in container mode.
_PSEUDO_FSTYPES = frozenset(
    {
        "autofs",
        "binfmt_misc",
        "bpf",
        "cgroup",
        "cgroup2",
        "configfs",
        "debugfs",
        "devpts",
        "devtmpfs",
        "fusectl",
        "hugetlbfs",
        "mqueue",
        "nsfs",
        "overlay",
        "proc",
        "pstore",
        "ramfs",
        "rpc_pipefs",
        "securityfs",
        "squashfs",
        "sysfs",
        "tmpfs",
        "tracefs",
    }
)

_HostPart = namedtuple("_HostPart", "device mountpoint fstype opts")
_HostUsage = namedtuple("_HostUsage", "total used free percent")


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

    def __init__(self, rootfs: Optional[str] = None) -> None:
        # Explicit override for tests; production derives it from HOST_PREFIX.
        self._rootfs_override = rootfs

    def _rootfs(self) -> Optional[str]:
        if self._rootfs_override is not None:
            return self._rootfs_override
        if not constants.HOST_PREFIX:
            return None
        candidate = constants.HOST_PREFIX + "/rootfs"
        return candidate if os.path.isdir(candidate) else None

    def partitions(self) -> list:
        rootfs = self._rootfs()
        if rootfs is None:
            if constants.HOST_PREFIX:
                # Container mode but the host root isn't mounted: psutil
                # would surface the container's overlay/bind mounts as host
                # disks. Skip rather than mislead.
                constants.LOG.warning(
                    "disk_usage: container mode but %s/rootfs is not mounted; "
                    "skipping (bind-mount the host root read-only to enable)",
                    constants.HOST_PREFIX,
                )
                return []
            try:
                return psutil.disk_partitions(all=False)
            except OSError:
                return []
        return _host_partitions(rootfs)

    def usage(self, mountpoint: str):
        """Usage for one mountpoint. Raises (``PermissionError``/``OSError``)
        for an unreadable mount — the caller skips that partition. In
        container mode the mountpoint is a host path measured through the
        rootfs mount."""
        rootfs = self._rootfs()
        if rootfs is None:
            return psutil.disk_usage(mountpoint)
        return _statvfs_usage(_join_rootfs(rootfs, mountpoint))

    def io_counters(self) -> dict:
        # /proc/diskstats is not namespaced, so psutil already reports the
        # host's per-device counters even from inside the container.
        try:
            return psutil.disk_io_counters(perdisk=True) or {}
        except (OSError, RuntimeError):
            return {}


def _unescape_mount_field(field: str) -> str:
    r"""Decode the octal escapes (\040 space, \011 tab, \012 nl, \134 \\)
    that /proc/mounts uses for whitespace in device/mountpoint fields."""
    if "\\" not in field:
        return field
    out, i = [], 0
    while i < len(field):
        if field[i] == "\\" and i + 3 < len(field) and field[i + 1 : i + 4].isdigit():
            out.append(chr(int(field[i + 1 : i + 4], 8)))
            i += 4
        else:
            out.append(field[i])
            i += 1
    return "".join(out)


def _parse_mounts(text: str) -> list:
    """Parse /proc/mounts content into ``_HostPart`` rows, dropping pseudo
    filesystems and de-duplicating by mountpoint (keeping the first, i.e.
    the underlying mount rather than a later overlay/bind of the same point)."""
    seen: set[str] = set()
    parts: list = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        device, mountpoint, fstype, opts = (
            _unescape_mount_field(fields[0]),
            _unescape_mount_field(fields[1]),
            fields[2],
            fields[3],
        )
        if fstype in _PSEUDO_FSTYPES or mountpoint in seen:
            continue
        seen.add(mountpoint)
        parts.append(_HostPart(device, mountpoint, fstype, opts))
    return parts


def _host_partitions(rootfs: str) -> list:
    """Read the host's mount table. With ``pid: host`` the container's
    ``/proc/1/mounts`` is the host init's mount namespace (the real host
    filesystems); fall back to the rootfs-mounted copy if that's
    unreadable."""
    for path in ("/proc/1/mounts", rootfs.rstrip("/") + "/proc/1/mounts"):
        try:
            with open(path, encoding="utf-8") as f:
                return _parse_mounts(f.read())
        except OSError:
            continue
    return []


def _join_rootfs(rootfs: str, mountpoint: str) -> str:
    """Resolve a host mountpoint to its path under the rootfs mount.
    ``("/host/rootfs", "/")`` → ``/host/rootfs``; ``(..., "/home")`` →
    ``/host/rootfs/home``."""
    return (
        rootfs.rstrip("/") + "/" + mountpoint.lstrip("/")
        if mountpoint != "/"
        else rootfs.rstrip("/") or "/"
    )


def _statvfs_usage(path: str) -> "_HostUsage":
    """``statvfs``-based usage matching psutil.disk_usage semantics: ``free``
    is space available to an unprivileged user and ``percent`` is computed
    against the user-visible total (used + avail), so reserved blocks don't
    skew it."""
    st = os.statvfs(path)
    total = st.f_blocks * st.f_frsize
    avail_root = st.f_bfree * st.f_frsize
    avail_user = st.f_bavail * st.f_frsize
    used = total - avail_root
    total_user = used + avail_user
    percent = round(used / total_user * 100, 1) if total_user > 0 else 0.0
    return _HostUsage(total=total, used=used, free=avail_user, percent=percent)


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
