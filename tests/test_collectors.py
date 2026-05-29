"""Tests for the host-path translation helpers and the Linux
launch_items collector — the exact code paths that crashed the
`launch_items` collector with an IndexError in container mode.

These are pure-filesystem tests: a temp directory stands in for the
container's HOST_PREFIX mount tree. No systemd, no journalctl, no
real OS binaries — so they run anywhere and would have caught the bug.

Why the bug slipped through before: the enrichment/dashboard/judge
layers were tested hard, but the collectors were waved off as
"needs OS binaries". The crash was NOT in OS-binary territory — it
was in `host_paths_for_home()` returning [] and the caller doing
`[...][0]`. Pure logic, fully unit-testable. This file closes that gap.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import avai.host_monitor as hm
from avai.host_monitor import LinuxLaunchItemsCollector, host_path, host_paths_for_home

# ---------------------------------------------------------------------------
# host_path — absolute-path translation under HOST_PREFIX
# ---------------------------------------------------------------------------


class TestHostPath:
    def test_passthrough_without_prefix(self, monkeypatch):
        monkeypatch.setattr(hm, "HOST_PREFIX", "")
        assert host_path("/etc/passwd") == Path("/etc/passwd")

    def test_prepends_prefix_when_set(self, monkeypatch):
        monkeypatch.setattr(hm, "HOST_PREFIX", "/host")
        assert host_path("/etc/passwd") == Path("/host/etc/passwd")

    def test_relative_path_is_passthrough_even_with_prefix(self, monkeypatch):
        monkeypatch.setattr(hm, "HOST_PREFIX", "/host")
        assert host_path("relative/dir") == Path("relative/dir")


# ---------------------------------------------------------------------------
# host_paths_for_home — the function whose empty-list return crashed
# the launch_items collector
# ---------------------------------------------------------------------------


class TestHostPathsForHome:
    def test_absolute_template_returns_single_translated_path(self, monkeypatch):
        monkeypatch.setattr(hm, "HOST_PREFIX", "/host")
        out = host_paths_for_home("/etc/systemd/system")
        assert out == [Path("/host/etc/systemd/system")]

    def test_home_template_without_prefix_expands_user_home(self, monkeypatch):
        monkeypatch.setattr(hm, "HOST_PREFIX", "")
        out = host_paths_for_home("~/.config/systemd/user")
        assert len(out) == 1
        assert str(out[0]).endswith("/.config/systemd/user")
        assert "~" not in str(out[0])  # expanduser ran

    def test_home_template_with_prefix_enumerates_user_homes(
        self, tmp_path, monkeypatch
    ):
        # Simulate /host/home/alice and /host/home/bob + /host/root.
        monkeypatch.setattr(hm, "HOST_PREFIX", str(tmp_path))
        (tmp_path / "home" / "alice").mkdir(parents=True)
        (tmp_path / "home" / "bob").mkdir(parents=True)
        (tmp_path / "root").mkdir()
        out = host_paths_for_home("~/.config/systemd/user")
        names = sorted(str(p) for p in out)
        assert any("home/alice/.config/systemd/user" in p for p in names)
        assert any("home/bob/.config/systemd/user" in p for p in names)
        assert any("root/.config/systemd/user" in p for p in names)
        assert len(out) == 3

    def test_home_template_with_prefix_but_no_homes_returns_empty(
        self, tmp_path, monkeypatch
    ):
        # *** This is the exact condition that crashed launch_items. ***
        # HOST_PREFIX is set, but neither <prefix>/home nor <prefix>/root
        # exist (e.g. only /proc and /sys were bind-mounted). The
        # function must return [] — and callers must tolerate it.
        monkeypatch.setattr(hm, "HOST_PREFIX", str(tmp_path))
        assert host_paths_for_home("~/.config/systemd/user") == []

    def test_only_root_home_present(self, tmp_path, monkeypatch):
        monkeypatch.setattr(hm, "HOST_PREFIX", str(tmp_path))
        (tmp_path / "root").mkdir()
        out = host_paths_for_home("~/.config/systemd/user")
        assert len(out) == 1
        assert "root/.config/systemd/user" in str(out[0])


# ---------------------------------------------------------------------------
# LinuxLaunchItemsCollector.collect() — the regression itself
# ---------------------------------------------------------------------------


def _write_unit(prefix: Path, rel_dir: str, name: str, body: str) -> None:
    d = prefix / rel_dir.lstrip("/")
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(body, encoding="utf-8")


class TestLinuxLaunchItemsCollect:
    def test_does_not_crash_when_no_home_or_root_mounted(self, tmp_path, monkeypatch):
        """THE regression test. Container mode with HOST_PREFIX set but
        no /host/home and no /host/root present. Pre-fix this raised
        IndexError and killed the collector; post-fix it must complete
        and still return the system units it can see."""
        monkeypatch.setattr(hm, "HOST_PREFIX", str(tmp_path))
        _write_unit(
            tmp_path,
            "/etc/systemd/system",
            "myapp.service",
            "[Unit]\nDescription=My App\n"
            "[Service]\nExecStart=/usr/bin/myapp --flag\n"
            "[Install]\nWantedBy=multi-user.target\n",
        )

        # Must not raise.
        rows = list(LinuxLaunchItemsCollector().collect())

        labels = [r["label"] for r in rows]
        assert "myapp" in labels
        row = next(r for r in rows if r["label"] == "myapp")
        assert row["program"] == "/usr/bin/myapp --flag"
        assert row["run_at_load"] == 1  # has [Install] WantedBy

    def test_collects_user_units_when_homes_present(self, tmp_path, monkeypatch):
        monkeypatch.setattr(hm, "HOST_PREFIX", str(tmp_path))
        _write_unit(
            tmp_path,
            "home/alice/.config/systemd/user",
            "agent.service",
            "[Service]\nExecStart=/home/alice/bin/agent\n",
        )
        rows = list(LinuxLaunchItemsCollector().collect())
        assert "agent" in [r["label"] for r in rows]

    def test_empty_prefix_tree_yields_nothing_no_crash(self, tmp_path, monkeypatch):
        # HOST_PREFIX points at an empty dir → no unit dirs exist → the
        # collector yields nothing and does not raise.
        monkeypatch.setattr(hm, "HOST_PREFIX", str(tmp_path))
        assert list(LinuxLaunchItemsCollector().collect()) == []

    def test_systemd_first_wins_dedup_across_dirs(self, tmp_path, monkeypatch):
        monkeypatch.setattr(hm, "HOST_PREFIX", str(tmp_path))
        # Same unit name in /etc (higher precedence) and /lib.
        _write_unit(
            tmp_path,
            "/etc/systemd/system",
            "dup.service",
            "[Service]\nExecStart=/etc/version\n",
        )
        _write_unit(
            tmp_path,
            "/lib/systemd/system",
            "dup.service",
            "[Service]\nExecStart=/lib/version\n",
        )
        rows = [r for r in LinuxLaunchItemsCollector().collect() if r["label"] == "dup"]
        assert len(rows) == 1
        assert rows[0]["program"] == "/etc/version"  # /etc wins


# ---------------------------------------------------------------------------
# _unit_row parsing
# ---------------------------------------------------------------------------


class TestUnitRow:
    def test_parses_restart_always_as_keep_alive(self, tmp_path):
        p = tmp_path / "x.service"
        p.write_text("[Service]\nExecStart=/bin/x\nRestart=always\n")
        row = LinuxLaunchItemsCollector._unit_row("system_service", p)
        assert row["keep_alive"] == 1

    def test_restart_no_is_not_keep_alive(self, tmp_path):
        p = tmp_path / "x.service"
        p.write_text("[Service]\nExecStart=/bin/x\nRestart=no\n")
        row = LinuxLaunchItemsCollector._unit_row("system_service", p)
        assert row["keep_alive"] == 0

    def test_timer_unit_uses_on_calendar_as_program(self, tmp_path):
        p = tmp_path / "x.timer"
        p.write_text("[Timer]\nOnCalendar=daily\n")
        row = LinuxLaunchItemsCollector._unit_row("system_timer", p)
        assert row["program"] == "daily"

    def test_malformed_unit_file_returns_none(self, tmp_path):
        # configparser chokes on a line with no section / no '=' →
        # must be swallowed, not raised.
        p = tmp_path / "bad.service"
        p.write_text("this is not a valid ini file at all\n%%%\n")
        # Either None or a row — but never an exception.
        try:
            row = LinuxLaunchItemsCollector._unit_row("system_service", p)
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"_unit_row raised on malformed input: {exc!r}")
        assert row is None or isinstance(row, dict)


# ---------------------------------------------------------------------------
# _cron_rows parsing
# ---------------------------------------------------------------------------


class TestCronRows:
    def test_system_crontab_with_user_column(self, tmp_path):
        p = tmp_path / "crontab"
        p.write_text("0 5 * * * root /usr/bin/backup.sh\n")
        rows = list(
            LinuxLaunchItemsCollector._cron_rows("system_crontab", p, has_user_col=True)
        )
        assert len(rows) == 1
        assert rows[0]["user_name"] == "root"
        assert rows[0]["program"] == "/usr/bin/backup.sh"

    def test_user_crontab_without_user_column(self, tmp_path):
        p = tmp_path / "alice"
        p.write_text("*/5 * * * * /home/alice/poll.sh\n")
        rows = list(
            LinuxLaunchItemsCollector._cron_rows(
                "user_crontab", p, has_user_col=False, default_user="alice"
            )
        )
        assert rows[0]["user_name"] == "alice"
        assert rows[0]["program"] == "/home/alice/poll.sh"

    def test_reboot_keyword_sets_run_at_load(self, tmp_path):
        p = tmp_path / "crontab"
        p.write_text("@reboot root /opt/startup\n")
        rows = list(
            LinuxLaunchItemsCollector._cron_rows("system_crontab", p, has_user_col=True)
        )
        assert rows[0]["run_at_load"] == 1

    def test_comments_blanks_and_env_lines_skipped(self, tmp_path):
        p = tmp_path / "crontab"
        p.write_text(
            "# a comment\n"
            "\n"
            "SHELL=/bin/bash\n"
            "PATH=/usr/bin:/bin\n"
            "0 0 * * * root /real/job\n"
        )
        rows = list(
            LinuxLaunchItemsCollector._cron_rows("system_crontab", p, has_user_col=True)
        )
        # Only the one real job — comment, blank, and 2 env lines dropped.
        assert len(rows) == 1
        assert rows[0]["program"] == "/real/job"

    def test_truncated_line_is_skipped_not_crashed(self, tmp_path):
        # A line with too few fields must be skipped, not IndexError.
        p = tmp_path / "crontab"
        p.write_text("0 5 *\n")  # only 3 of 5 schedule fields
        rows = list(
            LinuxLaunchItemsCollector._cron_rows("system_crontab", p, has_user_col=True)
        )
        assert rows == []

    def test_nonexistent_file_yields_nothing(self, tmp_path):
        rows = list(
            LinuxLaunchItemsCollector._cron_rows(
                "system_crontab", tmp_path / "missing", has_user_col=True
            )
        )
        assert rows == []
