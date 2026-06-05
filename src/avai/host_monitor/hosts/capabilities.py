"""Capability ports — the narrow abstractions the collectors depend on.

These are structural ``Protocol``s: a per-OS adapter satisfies one by
shape, no base class or registration required. Collectors receive the
capability they need (not the whole :class:`Host`), so they're trivially
faked in tests and carry no platform branches.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..collectors import SnapshotCollector, StreamingCollector
    from ..prompts import Prompts


@runtime_checkable
class FilesystemLayout(Protocol):
    """OS-varying filesystem *facts*. The collector owns the parsing; this
    just supplies the paths/args that differ per OS (Bridge), so a single
    shared parser runs everywhere."""

    def privileged_bin_dirs(self) -> list[Path]:
        """Directories to scan for setuid/setgid binaries."""
        ...

    def home_dirs(self) -> list[Path]:
        """Per-user home directories (for ``~/.ssh/authorized_keys`` etc.)."""
        ...

    def hosts_file(self) -> Path:
        """Path to the static hosts table."""
        ...

    def sudoers_file(self) -> Path:
        """Path to the main sudoers file."""
        ...

    def sudoers_dir(self) -> Path:
        """Path to the sudoers drop-in directory."""
        ...

    def tcpdump_interface_args(self) -> list[str]:
        """tcpdump flags that make each line carry its interface name
        (Linux ``-i any`` vs macOS ``-k I``)."""
        ...


@runtime_checkable
class PrivilegedAccounts(Protocol):
    """Privilege-granting account state where the whole gather differs per
    OS (directory-service queries vs ``/etc`` parsing)."""

    def privileged_group_members(self) -> Iterable[dict]:
        """Rows for members of admin/wheel/sudo groups."""
        ...

    def uid0_accounts(self) -> Iterable[dict]:
        """Rows for accounts with uid 0."""
        ...


@runtime_checkable
class Host(Protocol):
    """The platform object. Resolved once; assembles the collector set for
    this OS, wiring its capability ports into the OS-agnostic collectors."""

    def snapshot_collectors(self, prompts: "Prompts") -> "list[SnapshotCollector]": ...

    def streaming_collectors(
        self, prompts: "Prompts"
    ) -> "list[StreamingCollector]": ...
