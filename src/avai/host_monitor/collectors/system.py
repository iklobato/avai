"""Processes and host resources: the process table, CPU and memory meters,
disks and mounts."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from typing import Optional

try:
    import psutil
except ImportError:
    sys.stderr.write("Required: pip install psutil\n")
    sys.exit(2)

from .. import slices
from ..runtime import (
    Clock,
    DiskMetrics,
    SystemMetrics,
)
from .base import SnapshotCollector


class ProcessCollector(SnapshotCollector):
    slice = slices.PROCESSES
    judge_fields = ("name", "exe", "cmdline_json", "username")
    _ATTRS = [
        "pid",
        "ppid",
        "name",
        "exe",
        "cmdline",
        "username",
        "uids",
        "status",
        "create_time",
        "cpu_percent",
        "memory_info",
        "num_fds",
        "num_threads",
    ]

    def collect(self):
        for p in psutil.process_iter(self._ATTRS, ad_value=None):
            info = p.info
            mem, uids = info.get("memory_info"), info.get("uids")
            yield {
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name"),
                "exe": info.get("exe"),
                "cmdline_json": json.dumps(info.get("cmdline") or []),
                "username": info.get("username"),
                "uid": uids[0] if uids else None,
                "status": info.get("status"),
                "create_time": info.get("create_time"),
                "cpu_percent": info.get("cpu_percent"),
                "memory_rss": mem.rss if mem else None,
                "num_fds": info.get("num_fds"),
                "num_threads": info.get("num_threads"),
            }


class HostResourcesCollector(SnapshotCollector):
    """Aggregate resource meters (memory, swap, CPU, load, uptime, tasks) —
    the top-of-``htop`` panel, one row per cycle.

    psutil is the cross-platform port here, so there's no per-OS gather to
    vary: this is a single psutil-backed snapshot like
    :class:`ProcessCollector`, but the psutil calls go through the injected
    :class:`SystemMetrics` seam (testable without the global) and uptime is
    derived from the injected :class:`Clock` (deterministic in tests).

    A continuous metric, not a discrete artifact — ``judge_enabled=False``;
    the dashboard trends it instead of asking the LLM to classify it.
    """

    slice = slices.HOST_RESOURCES
    judge_enabled = False

    # Blocking CPU sample window (seconds). The monitor cycles every few
    # minutes, so a fraction of a second per cycle for an accurate reading
    # is negligible.
    CPU_INTERVAL = 0.15

    def __init__(
        self,
        metrics: Optional[SystemMetrics] = None,
        clock: Optional[Clock] = None,
        judge_hints: str = "",
    ):
        super().__init__(judge_hints=judge_hints)
        self._metrics = metrics or SystemMetrics()
        self._clock = clock or Clock()

    def collect(self):
        vm = self._metrics.virtual_memory()
        sm = self._metrics.swap_memory()
        sample = self._metrics.cpu_sample(self.CPU_INTERVAL)
        load = self._metrics.load_average()
        phys, logical = self._metrics.cpu_count()
        boot = self._metrics.boot_time()
        tasks = self._metrics.task_counts()

        cpu = self._cpu_aggregate(sample)
        now = datetime.fromisoformat(self._clock.now_iso()).timestamp()
        uptime = int(now - boot) if boot else None

        yield {
            "mem_total": getattr(vm, "total", None),
            "mem_available": getattr(vm, "available", None),
            "mem_used": getattr(vm, "used", None),
            "mem_free": getattr(vm, "free", None),
            "mem_percent": getattr(vm, "percent", None),
            "mem_active": getattr(vm, "active", None),
            "mem_inactive": getattr(vm, "inactive", None),
            "mem_buffers": getattr(vm, "buffers", None),
            "mem_cached": getattr(vm, "cached", None),
            "mem_wired": getattr(vm, "wired", None),
            "swap_total": getattr(sm, "total", None),
            "swap_used": getattr(sm, "used", None),
            "swap_free": getattr(sm, "free", None),
            "swap_percent": getattr(sm, "percent", None),
            "cpu_percent": cpu["percent"],
            "cpu_user": cpu["user"],
            "cpu_system": cpu["system"],
            "cpu_idle": cpu["idle"],
            "cpu_iowait": cpu["iowait"],
            "cpu_per_core_json": json.dumps(cpu["per_core"]),
            "cpu_count_physical": phys,
            "cpu_count_logical": logical,
            "load_1": load[0] if load else None,
            "load_5": load[1] if load else None,
            "load_15": load[2] if load else None,
            "boot_time": boot,
            "uptime_seconds": uptime,
            "tasks_total": tasks.get("total"),
            "tasks_running": tasks.get("running"),
            "threads_total": tasks.get("threads"),
        }

    @staticmethod
    def _cpu_aggregate(sample: list) -> dict:
        """Derive overall busy% + user/system/idle/iowait means + per-core
        busy% from one per-core times-percent sample. ``iowait`` is None on
        platforms (macOS/Windows) where psutil doesn't report it."""
        if not sample:
            return {
                "percent": None,
                "user": None,
                "system": None,
                "idle": None,
                "iowait": None,
                "per_core": [],
            }
        n = len(sample)

        def mean(attr):
            return sum(getattr(c, attr, 0.0) for c in sample) / n

        has_iowait = any(hasattr(c, "iowait") for c in sample)
        idle = mean("idle")
        return {
            "percent": round(100.0 - idle, 1),
            "user": round(mean("user"), 1),
            "system": round(mean("system"), 1),
            "idle": round(idle, 1),
            "iowait": round(mean("iowait"), 1) if has_iowait else None,
            "per_core": [round(100.0 - getattr(c, "idle", 0.0), 1) for c in sample],
        }


class DiskUsageCollector(SnapshotCollector):
    """Per-filesystem capacity + best-effort per-device I/O counters — the
    ``df`` table. One row per mounted filesystem per cycle, via the injected
    :class:`DiskMetrics` seam. Continuous metric → ``judge_enabled=False``.
    """

    slice = slices.DISK_USAGE
    judge_enabled = False

    def __init__(self, metrics: Optional[DiskMetrics] = None, judge_hints: str = ""):
        super().__init__(judge_hints=judge_hints)
        self._metrics = metrics or DiskMetrics()

    def collect(self):
        io = self._metrics.io_counters()
        for part in self._metrics.partitions():
            try:
                usage = self._metrics.usage(part.mountpoint)
            except (PermissionError, OSError):
                # Unreadable mount (permission, or a disconnected network
                # share) — a visible gap is the empty row's absence, not a
                # crash that kills the whole collector.
                continue
            counters = self._io_for(io, part.device)
            yield {
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "opts": part.opts,
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percent": usage.percent,
                "io_read_bytes": getattr(counters, "read_bytes", None),
                "io_write_bytes": getattr(counters, "write_bytes", None),
                "io_read_count": getattr(counters, "read_count", None),
                "io_write_count": getattr(counters, "write_count", None),
            }

    @staticmethod
    def _io_for(io: dict, device: Optional[str]):
        """Match a partition's device (``/dev/sda1``) to its per-disk I/O
        counters, which psutil keys by bare disk name (``sda1`` / ``disk0``).
        Returns None when there's no match (e.g. network/pseudo FS)."""
        if not device or not io:
            return None
        return io.get(device.rsplit("/", 1)[-1])


class MountsCollector(SnapshotCollector):
    """Cross-platform mount-table snapshot via ``psutil.disk_partitions``.

    Detects new mounts (an attacker shadowing ``/etc/passwd`` with a
    tmpfs is a classic rootkit move) and persistent device →
    mountpoint mappings. ``all=True`` keeps pseudo-filesystems
    (``proc``, ``sys``, ``tmpfs``, ``cgroup``, …) in the result —
    those are exactly what we want to watch for surprises.
    """

    slice = slices.MOUNTS
    judge_fields = ("device", "mountpoint", "fstype", "opts")

    def collect(self):
        try:
            partitions = psutil.disk_partitions(all=True)
        except (psutil.AccessDenied, PermissionError):
            return
        for p in partitions:
            yield {
                "device": p.device,
                "mountpoint": p.mountpoint,
                "fstype": p.fstype,
                "opts": p.opts,
                "raw_json": json.dumps(
                    {
                        "device": p.device,
                        "mountpoint": p.mountpoint,
                        "fstype": p.fstype,
                        "opts": p.opts,
                        "maxfile": getattr(p, "maxfile", None),
                        "maxpath": getattr(p, "maxpath", None),
                    }
                ),
            }
