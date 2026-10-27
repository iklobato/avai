"""The host's mount table and filesystem usage, read through a bind-mounted
host root when the monitor runs in a container."""

from __future__ import annotations

import os
from collections.abc import Iterable
from typing import NamedTuple

# Virtual / pseudo filesystems that carry no meaningful capacity — never
# part of a "df" view, and the bulk of what a container's own mount table
# is made of. Used to filter the host mount table in container mode.
PSEUDO_FSTYPES = frozenset(
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
# device mountpoint fstype options (dump and pass are optional)
MOUNTS_FIELDS = 4
OCTAL_ESCAPE_DIGITS = 3
OCTAL_BASE = 8
PERCENT = 100
PERCENT_DIGITS = 1
NO_USAGE_PERCENT = 0.0
HOST_MOUNT_FILES = ("/proc/1/mounts",)


class HostPart(NamedTuple):
    device: str
    mountpoint: str
    fstype: str
    opts: str


class HostUsage(NamedTuple):
    total: int
    used: int
    free: int
    percent: float


class MountField:
    r"""One /proc/mounts field, decoding the octal escapes (\040 space,
    \011 tab, \012 nl, \134 \\) used for whitespace in device/mountpoint."""

    def __init__(self, raw: str) -> None:
        self._raw = raw

    def decoded(self) -> str:
        if "\\" not in self._raw:
            return self._raw
        chars: list[str] = []
        index = 0
        while index < len(self._raw):
            escape = self._escape_at(index)
            chars.append(escape or self._raw[index])
            index += OCTAL_ESCAPE_DIGITS + 1 if escape else 1
        return "".join(chars)

    def _escape_at(self, index: int) -> str | None:
        digits = self._raw[index + 1 : index + 1 + OCTAL_ESCAPE_DIGITS]
        is_escape = (
            self._raw[index] == "\\"
            and index + OCTAL_ESCAPE_DIGITS < len(self._raw)
            and digits.isdigit()
        )
        return chr(int(digits, OCTAL_BASE)) if is_escape else None


class MountTable:
    """/proc/mounts content parsed into ``HostPart`` rows."""

    def __init__(self, text: str) -> None:
        self._text = text

    def parts(self) -> list[HostPart]:
        """Real filesystems, de-duplicated by mountpoint (keeping the first,
        i.e. the underlying mount rather than a later overlay/bind of the
        same point)."""
        seen: set[str] = set()
        parts: list[HostPart] = []
        for part in self._candidates():
            if part.fstype in PSEUDO_FSTYPES or part.mountpoint in seen:
                continue
            seen.add(part.mountpoint)
            parts.append(part)
        return parts

    def _candidates(self) -> Iterable[HostPart]:
        for line in self._text.splitlines():
            fields = line.split()
            if len(fields) < MOUNTS_FIELDS:
                continue
            device, mountpoint, fstype, opts = fields[:MOUNTS_FIELDS]
            yield HostPart(
                MountField(device).decoded(),
                MountField(mountpoint).decoded(),
                fstype,
                opts,
            )


class HostRootfs:
    """The host root bind-mounted into the container at ``path``."""

    def __init__(self, path: str) -> None:
        self._path = path

    def partitions(self) -> list[HostPart]:
        """Read the host's mount table. With ``pid: host`` the container's
        ``/proc/1/mounts`` is the host init's mount namespace (the real host
        filesystems); fall back to the rootfs-mounted copy if that's
        unreadable."""
        paths = (*HOST_MOUNT_FILES, self._path.rstrip("/") + "/proc/1/mounts")
        texts = (self._read(path) for path in paths)
        text = next((text for text in texts if text is not None), None)
        return MountTable(text).parts() if text is not None else []

    def _read(self, path: str) -> str | None:
        try:
            with open(path, encoding="utf-8") as stream:
                return stream.read()
        except OSError:
            return None

    def join(self, mountpoint: str) -> str:
        """Resolve a host mountpoint to its path under the rootfs mount.
        ``("/host/rootfs", "/")`` → ``/host/rootfs``; ``(..., "/home")`` →
        ``/host/rootfs/home``."""
        if mountpoint == "/":
            return self._path.rstrip("/") or "/"
        return self._path.rstrip("/") + "/" + mountpoint.lstrip("/")

    def usage(self, mountpoint: str) -> HostUsage:
        return StatvfsUsage(self.join(mountpoint)).usage()


class StatvfsUsage:
    """``statvfs``-based usage matching psutil.disk_usage semantics: ``free``
    is space available to an unprivileged user and ``percent`` is computed
    against the user-visible total (used + avail), so reserved blocks don't
    skew it."""

    def __init__(self, path: str) -> None:
        self._path = path

    def usage(self) -> HostUsage:
        stat = os.statvfs(self._path)
        total = stat.f_blocks * stat.f_frsize
        used = total - stat.f_bfree * stat.f_frsize
        avail_user = stat.f_bavail * stat.f_frsize
        total_user = used + avail_user
        percent = (
            round(used / total_user * PERCENT, PERCENT_DIGITS)
            if total_user > 0
            else NO_USAGE_PERCENT
        )
        return HostUsage(total=total, used=used, free=avail_user, percent=percent)
