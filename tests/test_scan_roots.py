"""Tests for the YARA scan-root discovery model (``file_scanner.roots``).

Pure logic + real temp directories: ``ScanRoot`` ordering and the
exclusion specifications are exercised directly, and the catalog runs
against ``tmp_path`` trees so ``is_scannable()`` is real with no mocks.
"""

from __future__ import annotations

from pathlib import Path

from avai.host_monitor.enums import ScanTier
from avai.host_monitor.file_scanner.roots import (
    ApplicationRootProvider,
    CompositeExclusion,
    DownloadsRootProvider,
    HomeRootProvider,
    PrivilegedBinRootProvider,
    PseudoFsExclusion,
    ScanRoot,
    ScanRootCatalog,
    StaticRootProvider,
)


class _FakeFs:
    """A FilesystemLayout fake: returns exactly the paths it is given."""

    def __init__(self, *, bin_dirs=(), homes=(), app_exes=()):
        self._bin_dirs = list(bin_dirs)
        self._homes = list(homes)
        self._app_exes = list(app_exes)

    def privileged_bin_dirs(self):
        return self._bin_dirs

    def home_dirs(self):
        return self._homes

    def app_executables(self):
        return self._app_exes


# --- ScanRoot ordering & containment (pure) ---------------------------------


def test_scan_root_orders_by_tier_first():
    baseline = ScanRoot(Path("/a"), ScanTier.BASELINE, "full_disk")
    critical = ScanRoot(Path("/z/deep/path"), ScanTier.CRITICAL, "privileged_bin")
    assert critical < baseline
    assert sorted([baseline, critical]) == [critical, baseline]


def test_scan_root_orders_shallower_before_deeper_within_tier():
    shallow = ScanRoot(Path("/usr"), ScanTier.CRITICAL, "x")
    deep = ScanRoot(Path("/usr/local/bin"), ScanTier.CRITICAL, "x")
    assert shallow < deep


def test_scan_root_contains_subtree_and_self():
    root = ScanRoot(Path("/usr"), ScanTier.BASELINE, "full_disk")
    child = ScanRoot(Path("/usr/bin"), ScanTier.CRITICAL, "privileged_bin")
    assert root.contains(child)
    assert root.contains(root)
    assert not child.contains(root)


def test_scan_root_is_scannable_false_for_missing(tmp_path):
    missing = ScanRoot(tmp_path / "nope", ScanTier.HIGH, "home")
    assert not missing.is_scannable()
    real = ScanRoot(tmp_path, ScanTier.HIGH, "home")
    assert real.is_scannable()


# --- Exclusion specifications (pure) ----------------------------------------


def test_pseudofs_exclusion_denies_kernel_filesystems():
    policy = PseudoFsExclusion()
    assert not policy.permits(Path("/proc"))
    assert not policy.permits(Path("/proc/1/maps"))
    assert not policy.permits(Path("/sys/kernel"))
    assert not policy.permits(Path("/dev/null"))
    assert policy.permits(Path("/usr/bin"))
    # A path merely prefixed by a denied name (not a path segment) is allowed.
    assert policy.permits(Path("/processes"))


def test_composite_exclusion_is_logical_and():
    allow_all = PseudoFsExclusion()

    class _DenyTmp:
        def permits(self, path: Path) -> bool:
            return "tmp" not in path.parts

    composite = CompositeExclusion([allow_all, _DenyTmp()])
    assert composite.permits(Path("/usr/bin"))
    assert not composite.permits(Path("/tmp/x"))  # second rule rejects
    assert not composite.permits(Path("/proc"))  # first rule rejects


# --- Providers --------------------------------------------------------------


def test_providers_tag_tier_and_origin(tmp_path):
    fs = _FakeFs(bin_dirs=[tmp_path], homes=[tmp_path])
    (bin_root,) = list(PrivilegedBinRootProvider(fs).roots())
    assert bin_root.tier is ScanTier.CRITICAL and bin_root.origin == "privileged_bin"
    (home_root,) = list(HomeRootProvider(fs).roots())
    assert home_root.tier is ScanTier.HIGH and home_root.origin == "home"
    (dl_root,) = list(DownloadsRootProvider(fs).roots())
    assert dl_root.path == tmp_path / "Downloads" and dl_root.origin == "downloads"


def test_application_provider_dedupes_executable_parents(tmp_path):
    macos = tmp_path / "App.app" / "Contents" / "MacOS"
    fs = _FakeFs(app_exes=[macos / "App", macos / "helper"])
    roots = list(ApplicationRootProvider(fs).roots())
    assert len(roots) == 1  # both executables share one parent dir
    assert roots[0].path == macos and roots[0].tier is ScanTier.MEDIUM


# --- ScanRootCatalog: the ordered, deduped plan -----------------------------


def test_catalog_plan_is_ordered_deduped_and_filtered(tmp_path):
    bins = tmp_path / "bin"
    home = tmp_path / "home"
    full = tmp_path  # baseline root that subsumes the others
    for d in (bins, home):
        d.mkdir()

    providers = [
        StaticRootProvider([full], ScanTier.BASELINE, "full_disk"),
        StaticRootProvider([bins], ScanTier.CRITICAL, "privileged_bin"),
        StaticRootProvider([home], ScanTier.HIGH, "home"),
        StaticRootProvider([tmp_path / "ghost"], ScanTier.HIGH, "home"),  # missing
    ]
    catalog = ScanRootCatalog(providers, PseudoFsExclusion())
    plan = catalog.plan()

    # Non-scannable 'ghost' dropped; remaining sorted CRITICAL→HIGH→BASELINE.
    assert [r.origin for r in plan] == ["privileged_bin", "home", "full_disk"]
    # The baseline root subsumes the hot corners but is NOT pruned — overlap
    # is the seen-cache's job; it just sorts last.
    assert plan[-1].path == full
    assert plan[-1].contains(plan[0])


def test_catalog_dedupes_same_path_keeping_highest_tier(tmp_path):
    providers = [
        StaticRootProvider([tmp_path], ScanTier.BASELINE, "full_disk"),
        StaticRootProvider([tmp_path], ScanTier.CRITICAL, "privileged_bin"),
    ]
    plan = ScanRootCatalog(providers, PseudoFsExclusion()).plan()
    assert len(plan) == 1
    assert plan[0].tier is ScanTier.CRITICAL  # most urgent tier wins


def test_catalog_excludes_pseudo_filesystems():
    # /proc exists on Linux; assert the policy keeps it out regardless of
    # whether it is scannable on this host.
    providers = [StaticRootProvider([Path("/proc")], ScanTier.BASELINE, "full_disk")]
    plan = ScanRootCatalog(providers, PseudoFsExclusion()).plan()
    assert plan == []
