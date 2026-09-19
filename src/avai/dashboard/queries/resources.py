"""Host resources: CPU and memory trend, disks and the mount tree."""

from __future__ import annotations

from sqlalchemy import (
    desc,
    select,
)
from sqlalchemy.orm import Session

from avai.host_monitor import (
    DiskUsageRow,
    HostResourceRow,
)

from .common import _existing_tables, _parse_json_list


def host_resources(session: Session, run_id: str) -> dict | None:
    """Latest aggregate resource meters (memory/swap/CPU/load/uptime/tasks)
    for ``run_id`` as ``{"row": HostResourceRow, "per_core": [float, …]}``,
    or None. Guarded for DBs written before the table existed."""
    if "host_resources" not in _existing_tables(session):
        return None
    row = session.execute(
        select(HostResourceRow).where(HostResourceRow.run_id == run_id).limit(1)
    ).scalar_one_or_none()
    if row is None:
        return None
    return {"row": row, "per_core": _parse_json_list(row.cpu_per_core_json)}


def disk_usage(session: Session, run_id: str) -> list[DiskUsageRow]:
    """Per-filesystem usage rows for ``run_id``, fullest first. [] when the
    table is absent (older DB) or the run collected none."""
    if "disk_usage" not in _existing_tables(session):
        return []
    rows = list(
        session.execute(
            select(DiskUsageRow).where(DiskUsageRow.run_id == run_id)
        ).scalars()
    )
    rows.sort(key=lambda r: r.percent if r.percent is not None else -1.0, reverse=True)
    return rows


# Pseudo / virtual / read-only loop filesystems that bloat a `df` view: snap
# squashfs images (one mount per installed snap), tmpfs, and kernel virtual
# filesystems. Hidden from the primary disk view — a typical Linux desktop has
# ~20 snap mounts drowning the 2-3 filesystems a person actually cares about.
_PSEUDO_FSTYPES = frozenset(
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


def primary_filesystems(rows: list[DiskUsageRow]) -> list[DiskUsageRow]:
    """The 'real' on-disk filesystems worth showing first: drop pseudo /
    virtual / snap-loop mounts and zero-capacity entries, fullest first.
    The full set stays available via :func:`mount_tree` (the 'all mounts'
    drawer)."""
    real = [
        r
        for r in rows
        if (r.fstype or "").lower() not in _PSEUDO_FSTYPES and (r.total or 0) > 0
    ]
    real.sort(key=lambda r: r.percent if r.percent is not None else -1.0, reverse=True)
    return real


def _path_components(mountpoint: str) -> tuple[str, ...]:
    """Path segments of a mountpoint, root ('/') being the empty tuple. Sorting
    by this key yields pre-order tree order: a parent always precedes its
    children, and siblings come out alphabetically."""
    return tuple(part for part in mountpoint.split("/") if part)


def _is_ancestor(parent: str, child: str) -> bool:
    """True if ``parent`` is a mountpoint strictly above ``child`` in the
    filesystem tree. Root is an ancestor of everything but itself."""
    if parent == child:
        return False
    if parent == "/":
        return True
    return child.startswith(parent + "/")


def mount_tree(rows: list[DiskUsageRow]) -> list[dict]:
    """Arrange filesystem rows as a mount-point tree for display.

    Each entry is ``{"row", "depth", "is_last"}``: ``depth`` is how many of the
    other mountpoints in this set sit above it (so a child filesystem indents
    under its parent), and ``is_last`` marks the last child of a given parent
    so the template can draw the correct branch glyph. Ordered as a pre-order
    walk (parent before children) rather than fullest-first; the usage bar and
    colour still surface a full filesystem at a glance.
    """
    rows = [r for r in rows if r.mountpoint]
    points = {r.mountpoint for r in rows}
    ordered = sorted(rows, key=lambda r: _path_components(r.mountpoint))

    nodes: list[dict] = []
    for row in ordered:
        ancestors = [m for m in points if _is_ancestor(m, row.mountpoint)]
        parent = max(ancestors, key=lambda m: len(_path_components(m)), default=None)
        nodes.append({"row": row, "depth": len(ancestors), "parent": parent})

    siblings: dict = {}
    for node in nodes:
        siblings.setdefault(node["parent"], []).append(node)
    for group in siblings.values():
        for node in group:
            node["is_last"] = node is group[-1]
    return nodes


def resource_trend(session: Session, limit: int = 60) -> dict:
    """Recent memory/CPU/swap percentages oldest→newest for the trend
    charts. Empty series when the table is absent."""
    empty = {"labels": [], "mem": [], "cpu": [], "swap": []}
    if "host_resources" not in _existing_tables(session):
        return empty
    rows = session.execute(
        select(
            HostResourceRow.collected_at,
            HostResourceRow.mem_percent,
            HostResourceRow.cpu_percent,
            HostResourceRow.swap_percent,
        )
        .order_by(desc(HostResourceRow.collected_at))
        .limit(limit)
    ).all()
    rows = list(reversed(rows))
    return {
        "labels": [r[0] for r in rows],
        "mem": [r[1] for r in rows],
        "cpu": [r[2] for r in rows],
        "swap": [r[3] for r in rows],
    }
