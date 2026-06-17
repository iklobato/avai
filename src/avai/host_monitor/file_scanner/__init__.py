"""Full-disk YARA scanning, decomposed into single-responsibility objects.

The first landed slice is the directory-discovery layer: an OO model that
produces the ordered, deduped, security-prioritized list of directories the
scanner walks. The matcher / seen-store / worker-pool / streaming-collector
slices compose against these same ports.
"""

from __future__ import annotations

from .roots import (
    ApplicationRootProvider,
    CompositeExclusion,
    DownloadsRootProvider,
    ExclusionPolicy,
    HomeRootProvider,
    PrivilegedBinRootProvider,
    PseudoFsExclusion,
    ScanRoot,
    ScanRootCatalog,
    ScanRootProvider,
    StaticRootProvider,
)

__all__ = [
    "ScanRoot",
    "ScanRootProvider",
    "ScanRootCatalog",
    "StaticRootProvider",
    "PrivilegedBinRootProvider",
    "HomeRootProvider",
    "DownloadsRootProvider",
    "ApplicationRootProvider",
    "ExclusionPolicy",
    "PseudoFsExclusion",
    "CompositeExclusion",
]
