"""Object model for discovering and ordering the directories a YARA scan
should walk — highest-signal corners first, the full-disk baseline last.

Everything here is behaviour-on-objects, by design: discovery lives in
:class:`ScanRootProvider` objects, ordering and validation in the
:class:`ScanRoot` value object, filtering in :class:`ExclusionPolicy`
objects, and aggregation in :class:`ScanRootCatalog`. There are no
module-level scoring or helper functions — the catalog's ``plan()`` is the
single entry point and returns the ordered, deduped directory list.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Protocol, runtime_checkable

from ..enums import ScanTier

if TYPE_CHECKING:
    from ..hosts.capabilities import FilesystemLayout


@dataclass(frozen=True)
class ScanRoot:
    """A directory to scan, with its security priority and provenance.

    Orders itself so a plain ``sorted()`` yields the scan order: lower tier
    first, then shallower paths (a parent before its children), then lexical
    — deterministic and explainable, with no external sort key.
    """

    path: Path
    tier: ScanTier
    origin: str

    @property
    def _order_key(self) -> tuple[int, int, str]:
        return (int(self.tier), len(self.path.parts), str(self.path))

    def __lt__(self, other: "ScanRoot") -> bool:
        return self._order_key < other._order_key

    def contains(self, other: "ScanRoot") -> bool:
        """True when ``other`` lies within this root's subtree (or is it).

        Used to reason about overlap (a full-disk root subsumes the hot
        corners); resolving the overlap is the scanner's seen-cache job, not
        this object's — it never drops the higher-priority child.
        """
        return other.path == self.path or other.path.is_relative_to(self.path)

    def is_scannable(self) -> bool:
        """A real, readable directory. Filters vanished/permission-denied
        roots at discovery time so the walker never starts on a dead path."""
        try:
            return self.path.is_dir() and os.access(self.path, os.R_OK)
        except OSError:
            return False


@runtime_checkable
class ScanRootProvider(Protocol):
    """One source of scan roots (a privileged-bin set, the home dirs, the
    full-disk baseline). New sources are new classes — the catalog never
    changes (OCP)."""

    def roots(self) -> Iterable[ScanRoot]: ...


class StaticRootProvider:
    """Fixed, known locations at one tier (launch-agent dirs, temp dirs,
    browser-profile roots, the full-disk root). The paths are injected at
    the composition root, so this carries no platform branches and is reused
    for every static source rather than duplicating a class per source."""

    def __init__(self, paths: Iterable[Path], tier: ScanTier, origin: str) -> None:
        self._paths = tuple(paths)
        self._tier = tier
        self._origin = origin

    def roots(self) -> Iterable[ScanRoot]:
        return (ScanRoot(p, self._tier, self._origin) for p in self._paths)


class PrivilegedBinRootProvider:
    """The setuid/privileged binary directories — top priority: a planted
    binary here runs with elevated reach. OS-varying paths come from the
    injected :class:`FilesystemLayout` (Bridge)."""

    def __init__(self, fs: "FilesystemLayout") -> None:
        self._fs = fs

    def roots(self) -> Iterable[ScanRoot]:
        return (
            ScanRoot(p, ScanTier.CRITICAL, "privileged_bin")
            for p in self._fs.privileged_bin_dirs()
        )


class HomeRootProvider:
    """Per-user home directories — high signal (user-writable, where
    delivered payloads and persistence land)."""

    def __init__(self, fs: "FilesystemLayout") -> None:
        self._fs = fs

    def roots(self) -> Iterable[ScanRoot]:
        return (ScanRoot(home, ScanTier.HIGH, "home") for home in self._fs.home_dirs())


class DownloadsRootProvider:
    """``~/Downloads`` for each home — the freshest delivery vector. The
    walker applies per-file recency; this just surfaces the directory."""

    _SUBDIR = "Downloads"

    def __init__(self, fs: "FilesystemLayout") -> None:
        self._fs = fs

    def roots(self) -> Iterable[ScanRoot]:
        return (
            ScanRoot(home / self._SUBDIR, ScanTier.HIGH, "downloads")
            for home in self._fs.home_dirs()
        )


class ApplicationRootProvider:
    """Directories holding installed application executables — medium
    priority. Derives the containing dirs from the layout's
    ``app_executables()`` so macOS bundles and the Linux empty set are both
    handled without a platform branch here."""

    def __init__(self, fs: "FilesystemLayout") -> None:
        self._fs = fs

    def roots(self) -> Iterable[ScanRoot]:
        seen: set[Path] = set()
        for exe in self._fs.app_executables():
            parent = exe.parent
            if parent not in seen:
                seen.add(parent)
                yield ScanRoot(parent, ScanTier.MEDIUM, "application")


@runtime_checkable
class ExclusionPolicy(Protocol):
    """Decides whether a path is allowed into the scan plan at all."""

    def permits(self, path: Path) -> bool: ...


class PseudoFsExclusion:
    """Reject kernel/virtual filesystems that hold no real files to scan
    (``/proc``, ``/sys``, ``/dev``) — walking them is pure waste and can
    hang on device nodes.

    Matches on the first path segment (``parts[1]`` after the root anchor)
    rather than a string prefix, so ``/processes`` is not mistaken for
    ``/proc`` and the rule is independent of the OS path separator.
    """

    _DENY = frozenset({"proc", "sys", "dev"})

    def permits(self, path: Path) -> bool:
        parts = path.parts
        return not (len(parts) >= 2 and parts[1] in self._DENY)


class CompositeExclusion:
    """Specification AND: a path is permitted only when every rule permits
    it. New rules (e.g. a device-boundary check) compose in without editing
    the catalog or the other rules."""

    def __init__(self, rules: Iterable[ExclusionPolicy]) -> None:
        self._rules = tuple(rules)

    def permits(self, path: Path) -> bool:
        return all(rule.permits(path) for rule in self._rules)


class ScanRootCatalog:
    """Aggregates every provider's roots into one ordered, deduped,
    security-prioritized scan plan — the single source of the directory
    list the scanner walks.

    ``plan()`` is pure with respect to its inputs given a fixed filesystem:
    discover from all providers, drop excluded and non-scannable roots,
    collapse exact-duplicate paths to their highest priority, and sort.
    """

    def __init__(
        self, providers: Iterable[ScanRootProvider], exclusions: ExclusionPolicy
    ) -> None:
        self._providers = tuple(providers)
        self._exclusions = exclusions

    def plan(self) -> list[ScanRoot]:
        return sorted(self._dedupe_to_highest_tier(self._discover()))

    def _discover(self) -> Iterable[ScanRoot]:
        for provider in self._providers:
            for root in provider.roots():
                if self._exclusions.permits(root.path) and root.is_scannable():
                    yield root

    @staticmethod
    def _dedupe_to_highest_tier(roots: Iterable[ScanRoot]) -> Iterable[ScanRoot]:
        # Two providers can surface the same path (a home dir that is also a
        # bin dir); keep the most urgent tier so it scans at its best priority.
        best: dict[Path, ScanRoot] = {}
        for root in roots:
            current = best.get(root.path)
            if current is None or root.tier < current.tier:
                best[root.path] = root
        return best.values()
