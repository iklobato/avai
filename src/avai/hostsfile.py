"""Map ``avai.local`` (or any name) onto loopback in the OS hosts file so the
dashboard is reachable by name rather than by ``127.0.0.1:<port>``.

Editing the system hosts table is privileged and platform-specific, so the
concern is split along three SOLID seams:

- :class:`Platform` — a structural ``Protocol`` (DIP/ISP) for the OS-varying
  facts: *where* the hosts file lives and *how* to gain write access. One
  concrete strategy per OS family; :func:`resolve_platform` is the single
  platform-detection point (mirrors ``host_monitor.hosts.HostFactory``).
- :class:`HostsTable` — a pure, I/O-free transform of the file's text. It
  owns the idempotent, marker-delimited managed block and leaves every other
  line untouched, so the parsing/rewrite logic is unit-testable without root.
- :class:`HostsRegistrar` — orchestrates read → transform → atomic write
  through an injected ``Platform``, translating a raw ``PermissionError`` at
  the boundary into a typed, actionable :class:`HostsPermissionError`.

There is deliberately no pip post-install hook: wheels can't run install-time
code portably, and a ``pip install`` has neither the privilege nor the right
to edit a system file. The privileged ``avai install-hosts`` command (and the
dashboard's best-effort :meth:`HostsRegistrar.ensure_reachable` on launch) are
the supported entry points.
"""

from __future__ import annotations

import os
import platform
import re
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol, runtime_checkable

DASHBOARD_HOSTNAME = "avai.local"
LOOPBACK_IPV4 = "127.0.0.1"
LOOPBACK_IPV6 = "::1"
# Map both loopback families. macOS reserves the ``.local`` TLD for mDNS, so a
# getaddrinfo() (curl/browsers/requests) asks mDNSResponder for the AAAA record;
# if only the IPv4 line is present it waits out the ~5s multicast timeout before
# falling back to /etc/hosts. Listing ``::1`` too lets the AAAA query resolve
# from the hosts file immediately, so every request is instant.
LOOPBACK_ADDRESSES = (LOOPBACK_IPV4, LOOPBACK_IPV6)

# The managed block is delimited by these markers so edits are idempotent and
# reversible without disturbing the user's own entries.
_BLOCK_BEGIN = "# >>> avai >>>"
_BLOCK_END = "# <<< avai <<<"
_BLOCK_NOTE = "# managed by `avai install-hosts` — do not edit between the markers"

# A pragmatic hostname check (RFC-1123 labels). avai.local passes; this exists
# to reject obvious junk a caller might pass via --hostname, validated once at
# the API edge so the transform below can assume a clean value.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})*$")


class HostsError(RuntimeError):
    """Base class for hosts-file management failures."""


class UnsupportedPlatformError(HostsError):
    def __init__(self, system: str) -> None:
        super().__init__(f"avai cannot manage the hosts file on platform {system!r}")
        self.system = system


class HostsPermissionError(HostsError):
    """The hosts file exists but can't be written without more privilege."""

    def __init__(self, path: Path, hint: str) -> None:
        super().__init__(f"cannot write {path}: {hint}")
        self.path = path
        self.hint = hint


@runtime_checkable
class Platform(Protocol):
    """OS-varying hosts-file facts the registrar depends on (DIP)."""

    def hosts_path(self) -> Path:
        """Absolute path to the live system hosts file."""
        ...

    def elevation_hint(self, path: Path) -> str:
        """How to retry with enough privilege to write ``path``."""
        ...


class _PosixPlatform:
    """macOS and Linux: ``/etc/hosts``, writable by root."""

    def hosts_path(self) -> Path:
        return Path("/etc/hosts")

    def elevation_hint(self, path: Path) -> str:
        return f"re-run with sudo, e.g. `sudo avai install-hosts` (writes {path})"


class _WindowsPlatform:
    """Windows: ``%SystemRoot%\\System32\\drivers\\etc\\hosts``, writable by
    an elevated (Administrator) process."""

    def hosts_path(self) -> Path:
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        return Path(system_root) / "System32" / "drivers" / "etc" / "hosts"

    def elevation_hint(self, path: Path) -> str:
        return (
            f"run `avai install-hosts` from an Administrator terminal (writes {path})"
        )


def resolve_platform(system: str | None = None) -> Platform:
    """Select the hosts-file strategy for the current (or a named) OS.

    The single point that reads ``platform.system()``; an unsupported OS
    fails loudly here rather than producing a wrong path later.
    """
    name = system if system is not None else platform.system()
    if name in ("Darwin", "Linux"):
        return _PosixPlatform()
    if name == "Windows":
        return _WindowsPlatform()
    raise UnsupportedPlatformError(name)


def _entry_hostnames(line: str) -> list[str]:
    """Hostnames declared by an active (non-comment) hosts line; ``[]`` for
    blank/comment lines. The first whitespace-separated token is the address."""
    body = line.split("#", 1)[0].strip()
    if not body:
        return []
    return body.split()[1:]


@dataclass(frozen=True)
class HostsTable:
    """An I/O-free view of a hosts file's text.

    Mutations add/remove avai-managed entries inside the marker-delimited
    block, returning a new instance and leaving all other lines verbatim. The
    file's dominant line ending is preserved so a Windows CRLF file stays CRLF.
    """

    text: str

    def resolves(self, hostname: str) -> bool:
        """True if *any* active line maps ``hostname`` — including one the user
        added by hand outside our block. Used to avoid nagging/duplicating."""
        return any(hostname in _entry_hostnames(ln) for ln in self.text.splitlines())

    def is_managed(self, hostname: str) -> bool:
        """True only if ``hostname`` lives inside the avai-managed block."""
        return hostname in self._block_entries()

    def with_mapping(self, hostname: str, ips: tuple[str, ...]) -> "HostsTable":
        """Map ``hostname`` to one line per address in ``ips`` (e.g. an IPv4 and
        an IPv6 loopback), replacing any existing managed lines for it."""
        entries = self._block_entries()
        if entries.get(hostname) == list(ips):
            return self
        entries[hostname] = list(ips)
        return HostsTable(self._rewrite(entries))

    def without(self, hostname: str) -> "HostsTable":
        entries = self._block_entries()
        if hostname not in entries:
            return self
        del entries[hostname]
        return HostsTable(self._rewrite(entries))

    def _newline(self) -> str:
        return "\r\n" if "\r\n" in self.text else "\n"

    def _split_block(self) -> tuple[list[str], list[str], list[str]]:
        """Split lines into (before, inside-block, after). No (or malformed)
        markers → everything is 'before' and the block is empty."""
        lines = self.text.splitlines()
        try:
            begin = lines.index(_BLOCK_BEGIN)
            end = lines.index(_BLOCK_END)
        except ValueError:
            return lines, [], []
        if end < begin:
            return lines, [], []
        return lines[:begin], lines[begin + 1 : end], lines[end + 1 :]

    def _block_entries(self) -> dict[str, list[str]]:
        _before, block, _after = self._split_block()
        entries: dict[str, list[str]] = {}
        for line in block:
            names = _entry_hostnames(line)
            if not names:
                continue
            ip = line.split()[0]
            for name in names:
                ips = entries.setdefault(name, [])
                if ip not in ips:
                    ips.append(ip)
        return entries

    def _rewrite(self, entries: dict[str, list[str]]) -> str:
        before, _block, after = self._split_block()
        rebuilt = list(before)
        if entries:
            rebuilt.append(_BLOCK_BEGIN)
            rebuilt.append(_BLOCK_NOTE)
            rebuilt += [f"{ip}\t{name}" for name, ips in entries.items() for ip in ips]
            rebuilt.append(_BLOCK_END)
        rebuilt += after
        newline = self._newline()
        text = newline.join(rebuilt)
        if text and not text.endswith(newline):
            text += newline
        return text


class Outcome(Enum):
    CREATED = "created"
    REMOVED = "removed"
    UNCHANGED = "unchanged"
    NEEDS_PRIVILEGE = "needs_privilege"


def _validate_hostname(hostname: str) -> None:
    if not _HOSTNAME_RE.match(hostname) or len(hostname) > 253:
        raise HostsError(f"invalid hostname: {hostname!r}")


def _atomic_write(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` via a same-directory temp file + ``os.replace``
    so a crash mid-write can't leave a truncated hosts file. Preserves the
    existing file mode (hosts files are world-readable, 0644)."""
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".avai-hosts-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


class HostsRegistrar:
    """Read → transform → atomic-write the hosts file through a ``Platform``."""

    def __init__(self, platform_: Platform) -> None:
        self._platform = platform_

    @classmethod
    def for_current_platform(cls) -> "HostsRegistrar":
        return cls(resolve_platform())

    @property
    def hosts_path(self) -> Path:
        return self._platform.hosts_path()

    def resolves(self, hostname: str = DASHBOARD_HOSTNAME) -> bool:
        return self._read().resolves(hostname)

    def install(
        self,
        hostname: str = DASHBOARD_HOSTNAME,
        ips: tuple[str, ...] = LOOPBACK_ADDRESSES,
    ) -> Outcome:
        _validate_hostname(hostname)
        table = self._read()
        updated = table.with_mapping(hostname, ips)
        if updated.text == table.text:
            return Outcome.UNCHANGED
        self._write(updated.text)
        return Outcome.CREATED

    def remove(self, hostname: str = DASHBOARD_HOSTNAME) -> Outcome:
        table = self._read()
        updated = table.without(hostname)
        if updated.text == table.text:
            return Outcome.UNCHANGED
        self._write(updated.text)
        return Outcome.REMOVED

    def ensure_reachable(
        self,
        hostname: str = DASHBOARD_HOSTNAME,
        ips: tuple[str, ...] = LOOPBACK_ADDRESSES,
    ) -> Outcome:
        """Best-effort install for the dashboard's launch path: map the name if
        we already have write access, otherwise report ``NEEDS_PRIVILEGE``
        instead of raising — a missing hosts entry must never stop serving."""
        if self.resolves(hostname):
            return Outcome.UNCHANGED
        try:
            return self.install(hostname, ips)
        except HostsPermissionError:
            return Outcome.NEEDS_PRIVILEGE

    def _read(self) -> HostsTable:
        try:
            return HostsTable(self.hosts_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return HostsTable("")

    def _write(self, text: str) -> None:
        path = self.hosts_path
        try:
            _atomic_write(path, text)
        except PermissionError as e:
            raise HostsPermissionError(path, self._platform.elevation_hint(path)) from e
