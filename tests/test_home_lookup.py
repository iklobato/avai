"""A host with no findable home directory (no HOME and no passwd entry, as
in some containers) makes the per-user collectors find nothing, not fail."""

from __future__ import annotations

import pytest

from avai.host_monitor.collectors import InstalledAppsCollector, QuarantineCollector
from avai.host_monitor.runtime import HostPaths


@pytest.fixture
def homeless(monkeypatch: pytest.MonkeyPatch) -> None:
    # The user-database lookup only exists on Unix; Windows has no such case.
    user_database = pytest.importorskip("pwd")
    monkeypatch.delenv("HOME", raising=False)

    def no_entry(uid: int) -> object:
        raise KeyError(f"getpwuid(): uid not found: {uid}")

    monkeypatch.setattr(user_database, "getpwuid", no_entry)


class TestNoHomeDirectory:
    def test_installed_apps_still_reads_the_system_folder(self, homeless: None) -> None:
        rows = list(InstalledAppsCollector(HostPaths("")).collect())
        assert all(not row["path"].startswith("~") for row in rows)

    def test_quarantine_finds_nothing_instead_of_failing(self, homeless: None) -> None:
        assert list(QuarantineCollector().collect()) == []
