from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from datetime import datetime
from typing import Any

from .. import slices
from ..runtime import Clock, DiskMetrics, SystemMetrics
from .base import SnapshotCollector

PERCENT = 100.0
PERCENT_DIGITS = 1
NO_CPU_TIME = 0.0
MEMORY_FIELDS = (
    "total",
    "available",
    "used",
    "free",
    "percent",
    "active",
    "inactive",
    "buffers",
    "cached",
    "wired",
)
SWAP_FIELDS = ("total", "used", "free", "percent")
LOAD_COLUMNS = ("load_1", "load_5", "load_15")
CPU_MEAN_COLUMNS = ("cpu_percent", "cpu_user", "cpu_system", "cpu_idle", "cpu_iowait")
PART_FIELDS = ("device", "mountpoint", "fstype", "opts")
USAGE_FIELDS = ("total", "used", "free", "percent")
IO_FIELDS = ("read_bytes", "write_bytes", "read_count", "write_count")
MOUNT_LIMIT_FIELDS = ("maxfile", "maxpath")


class ProcessCollector(SnapshotCollector):
    slice = slices.PROCESSES
    judge_fields = ("name", "exe", "cmdline_json", "username")
    ATTRS = [
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

    def __init__(self, metrics: SystemMetrics, judge_hints: str = "") -> None:
        super().__init__(judge_hints)
        self._metrics = metrics

    def collect(self) -> Iterator[dict[str, Any]]:
        for proc in self._metrics.process_table(self.ATTRS):
            mem, uids = proc.get("memory_info"), proc.get("uids")
            yield {
                "pid": proc.get("pid"),
                "ppid": proc.get("ppid"),
                "name": proc.get("name"),
                "exe": proc.get("exe"),
                "cmdline_json": json.dumps(proc.get("cmdline") or []),
                "username": proc.get("username"),
                "uid": uids[0] if uids else None,
                "status": proc.get("status"),
                "create_time": proc.get("create_time"),
                "cpu_percent": proc.get("cpu_percent"),
                "memory_rss": mem.rss if mem else None,
                "num_fds": proc.get("num_fds"),
                "num_threads": proc.get("num_threads"),
            }


class CpuSample:
    """One per-core times-percent sample: overall busy% + user/system/idle/
    iowait means + per-core busy%. ``iowait`` is None on platforms
    (macOS/Windows) where psutil doesn't report it."""

    def __init__(self, cores: list[Any]) -> None:
        self._cores = cores

    def columns(self) -> dict[str, Any]:
        if not self._cores:
            return {**dict.fromkeys(CPU_MEAN_COLUMNS), "cpu_per_core_json": "[]"}
        idle = self._mean("idle")
        has_iowait = any(hasattr(core, "iowait") for core in self._cores)
        return {
            "cpu_percent": round(PERCENT - idle, PERCENT_DIGITS),
            "cpu_user": round(self._mean("user"), PERCENT_DIGITS),
            "cpu_system": round(self._mean("system"), PERCENT_DIGITS),
            "cpu_idle": round(idle, PERCENT_DIGITS),
            "cpu_iowait": (
                round(self._mean("iowait"), PERCENT_DIGITS) if has_iowait else None
            ),
            "cpu_per_core_json": json.dumps(self._per_core()),
        }

    def _mean(self, attr: str) -> float:
        total = sum(getattr(core, attr, NO_CPU_TIME) for core in self._cores)
        return total / len(self._cores)

    def _per_core(self) -> list[float]:
        return [
            round(PERCENT - getattr(core, "idle", NO_CPU_TIME), PERCENT_DIGITS)
            for core in self._cores
        ]


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
        self, metrics: SystemMetrics, clock: Clock, judge_hints: str = ""
    ) -> None:
        super().__init__(judge_hints=judge_hints)
        self._metrics = metrics
        self._clock = clock

    def collect(self) -> Iterator[dict[str, Any]]:
        physical, logical = self._metrics.cpu_count()
        boot = self._metrics.boot_time()
        tasks = self._metrics.task_counts()
        yield {
            **self._memory(),
            **CpuSample(self._metrics.cpu_sample(self.CPU_INTERVAL)).columns(),
            **self._load(),
            "cpu_count_physical": physical,
            "cpu_count_logical": logical,
            "boot_time": boot,
            "uptime_seconds": self._uptime(boot),
            "tasks_total": tasks.get("total"),
            "tasks_running": tasks.get("running"),
            "threads_total": tasks.get("threads"),
        }

    def _memory(self) -> dict[str, Any]:
        memory = self._metrics.virtual_memory()
        swap = self._metrics.swap_memory()
        return {
            **{f"mem_{field}": getattr(memory, field, None) for field in MEMORY_FIELDS},
            **{f"swap_{field}": getattr(swap, field, None) for field in SWAP_FIELDS},
        }

    def _load(self) -> dict[str, float | None]:
        load = self._metrics.load_average() or (None, None, None)
        return dict(zip(LOAD_COLUMNS, load))

    def _uptime(self, boot: float) -> int | None:
        if not boot:
            return None
        now = datetime.fromisoformat(self._clock.now_iso()).timestamp()
        return int(now - boot)


class DiskUsageCollector(SnapshotCollector):
    """Per-filesystem capacity + best-effort per-device I/O counters — the
    ``df`` table. One row per mounted filesystem per cycle, via the injected
    :class:`DiskMetrics` seam. Continuous metric → ``judge_enabled=False``.
    """

    slice = slices.DISK_USAGE
    judge_enabled = False

    def __init__(self, metrics: DiskMetrics, judge_hints: str = "") -> None:
        super().__init__(judge_hints=judge_hints)
        self._metrics = metrics

    def collect(self) -> Iterator[dict[str, Any]]:
        io = self._metrics.io_counters()
        for part in self._metrics.partitions():
            try:
                usage = self._metrics.usage(part.mountpoint)
            except (PermissionError, OSError):
                # Unreadable mount (permission, or a disconnected network
                # share) — a visible gap is the empty row's absence, not a
                # crash that kills the whole collector.
                continue
            counters = self.io_for(io, part.device)
            yield {
                **{field: getattr(part, field) for field in PART_FIELDS},
                **{field: getattr(usage, field) for field in USAGE_FIELDS},
                **{
                    f"io_{field}": getattr(counters, field, None) for field in IO_FIELDS
                },
            }

    def io_for(self, io: Mapping[str, object], device: str | None) -> object | None:
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

    def __init__(self, disks: DiskMetrics, judge_hints: str = "") -> None:
        super().__init__(judge_hints)
        self._disks = disks

    def collect(self) -> Iterator[dict[str, Any]]:
        for part in self._disks.mount_table():
            mount = {
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "opts": part.opts,
            }
            limits = {field: getattr(part, field, None) for field in MOUNT_LIMIT_FIELDS}
            yield {**mount, "raw_json": json.dumps({**mount, **limits})}
