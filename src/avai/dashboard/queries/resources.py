"""Host resources: CPU and memory trend, disks and the mount tree."""

from __future__ import annotations

from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from avai.host_monitor import DiskUsageRow, HostResourceRow

from .panel_reads import SchemaProbe, StoredJson

# Pseudo / virtual / read-only loop filesystems that bloat a `df` view: snap
# squashfs images (one mount per installed snap), tmpfs, and kernel virtual
# filesystems. Hidden from the primary disk view: a typical Linux desktop has
# ~20 snap mounts drowning the 2-3 filesystems a person actually cares about.
PSEUDO_FSTYPES = frozenset(
    {
        "squashfs",
        "tmpfs",
        "devtmpfs",
        "overlay",
        "ramfs",
        "efivarfs",
        "proc",
        "sysfs",
        "cgroup",
        "cgroup2",
        "debugfs",
        "mqueue",
        "hugetlbfs",
        "pstore",
        "autofs",
        "binfmt_misc",
        "tracefs",
        "securityfs",
        "configfs",
        "fusectl",
        "nsfs",
        "fuse.gvfsd-fuse",
        "fuse.portal",
    }
)


class ResourceQueries:
    """Resource meters and disk usage; each guarded for DBs written before
    its table existed."""

    TREND_POINTS = 60

    def __init__(self, session: Session) -> None:
        self._session = session

    def host_resources(self, run_id: str) -> dict[str, Any] | None:
        """Latest aggregate meters (memory/swap/CPU/load/uptime/tasks) as
        ``{"row": HostResourceRow, "per_core": [float, ...]}``, or None."""
        if "host_resources" not in SchemaProbe(self._session).tables():
            return None
        statement = (
            select(HostResourceRow).where(HostResourceRow.run_id == run_id).limit(1)
        )
        row = self._session.execute(statement).scalar_one_or_none()
        if row is None:
            return None
        return {"row": row, "per_core": StoredJson().as_list(row.cpu_per_core_json)}

    def disk_usage(self, run_id: str) -> list[DiskUsageRow]:
        """Per-filesystem usage rows, fullest first. [] when absent."""
        if "disk_usage" not in SchemaProbe(self._session).tables():
            return []
        statement = select(DiskUsageRow).where(DiskUsageRow.run_id == run_id)
        rows = list(self._session.execute(statement).scalars())
        return sorted(rows, key=DiskOrder().fullness, reverse=True)

    def resource_trend(self, limit: int = TREND_POINTS) -> dict[str, list[Any]]:
        """Recent memory/CPU/swap percentages oldest to newest for the trend
        charts. Empty series when the table is absent."""
        if "host_resources" not in SchemaProbe(self._session).tables():
            return {"labels": [], "mem": [], "cpu": [], "swap": []}
        statement = (
            select(
                HostResourceRow.collected_at,
                HostResourceRow.mem_percent,
                HostResourceRow.cpu_percent,
                HostResourceRow.swap_percent,
            )
            .order_by(desc(HostResourceRow.collected_at))
            .limit(limit)
        )
        rows = list(reversed(self._session.execute(statement).all()))
        labels, mem, cpu, swap = (
            (list(series) for series in zip(*rows)) if rows else ([], [], [], [])
        )
        return {"labels": labels, "mem": mem, "cpu": cpu, "swap": swap}


class DiskOrder:
    def fullness(self, row: DiskUsageRow) -> float:
        return row.percent if row.percent is not None else -1.0

    def primary(self, rows: list[DiskUsageRow]) -> list[DiskUsageRow]:
        """The 'real' on-disk filesystems worth showing first: no pseudo /
        virtual / snap-loop mounts or zero-capacity entries, fullest first.
        The full set stays available via :class:`MountTree`."""
        real = [
            row
            for row in rows
            if (row.fstype or "").lower() not in PSEUDO_FSTYPES and (row.total or 0) > 0
        ]
        return sorted(real, key=self.fullness, reverse=True)


class MountTree:
    """Filesystem rows arranged as a mount-point tree for display.

    Each entry is ``{"row", "depth", "parent", "is_last"}``: ``depth`` is how
    many of the other mountpoints sit above it (so a child filesystem indents
    under its parent) and ``is_last`` marks the last child of a parent so the
    template can draw the right branch glyph. Ordered as a pre-order walk
    (parent before children), not fullest first."""

    def nodes(self, rows: list[DiskUsageRow]) -> list[dict[str, Any]]:
        mounted = [row for row in rows if row.mountpoint]
        points = {row.mountpoint for row in mounted}
        ordered = sorted(mounted, key=self._components_of_row)
        nodes = [self._node(row, points) for row in ordered]
        siblings: dict[str | None, list[dict[str, Any]]] = {}
        for node in nodes:
            siblings.setdefault(node["parent"], []).append(node)
        for node in nodes:
            node["is_last"] = node is siblings[node["parent"]][-1]
        return nodes

    def _node(self, row: DiskUsageRow, points: set[str]) -> dict[str, Any]:
        ancestors = [
            point for point in points if self._is_ancestor(point, row.mountpoint)
        ]
        parent = max(ancestors, key=self._depth, default=None)
        return {"row": row, "depth": len(ancestors), "parent": parent}

    def _components_of_row(self, row: DiskUsageRow) -> tuple[str, ...]:
        return self._components(row.mountpoint)

    def _depth(self, mountpoint: str) -> int:
        return len(self._components(mountpoint))

    def _components(self, mountpoint: str) -> tuple[str, ...]:
        """Path segments of a mountpoint, root being the empty tuple. Sorting
        by this yields pre-order tree order: a parent precedes its children,
        siblings alphabetically."""
        return tuple(part for part in mountpoint.split("/") if part)

    def _is_ancestor(self, parent: str, child: str) -> bool:
        """True if ``parent`` is a mountpoint strictly above ``child``. Root
        is an ancestor of everything but itself."""
        if parent == child:
            return False
        return parent == "/" or child.startswith(parent + "/")
