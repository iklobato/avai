"""CLI dispatcher tests.

Covers the subcommand routing in :mod:`avai.cli` and the version /
help short-circuits — without touching ``host_monitor`` or
``dashboard`` (their ``main`` functions are mocked).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from avai import __version__
from avai.cli import main


class TestVersionFlag:
    @pytest.mark.parametrize("flag", ["-v", "--version"])
    def test_prints_version_and_exits_zero(self, flag, capsys):
        rc = main([flag])
        out = capsys.readouterr().out.strip()
        assert rc == 0
        assert out == __version__


class TestHelpFlag:
    @pytest.mark.parametrize("argv", [[], ["-h"], ["--help"], ["help"]])
    def test_no_args_or_help_shows_usage(self, argv, capsys):
        rc = main(argv)
        out = capsys.readouterr().out
        assert rc == 0
        assert "avai monitor" in out
        assert "avai dashboard" in out


class TestDispatch:
    @pytest.mark.parametrize("alias", ["monitor", "start", "scan"])
    def test_monitor_aliases_route_to_host_monitor(self, alias):
        with patch("avai.host_monitor.main", return_value=0) as m:
            rc = main([alias, "--once"])
        assert rc == 0
        m.assert_called_once_with()

    @pytest.mark.parametrize("alias", ["dashboard", "ui", "serve"])
    def test_dashboard_aliases_route_to_dashboard(self, alias):
        with patch("avai.dashboard.main", return_value=0) as d:
            rc = main([alias, "--port", "9000"])
        assert rc == 0
        d.assert_called_once_with()

    @pytest.mark.parametrize(
        "cmd,target",
        [("monitor", "avai.host_monitor"), ("dashboard", "avai.dashboard")],
    )
    def test_remaining_argv_passed_through(self, cmd, target):
        """sys.argv is rewritten so the called main() sees only its
        own arguments: the original subcommand token is dropped."""
        import sys

        captured: list[str] = []

        def fake_main():
            captured.extend(sys.argv)
            return 0

        with patch(f"{target}.main", side_effect=fake_main):
            main([cmd, "--once", "--db", "/tmp/x"])

        assert captured[0] == f"avai {cmd}"
        assert captured[1:] == ["--once", "--db", "/tmp/x"]


class TestAppCommand:
    @pytest.mark.parametrize("alias", ["app", "gui", "desktop"])
    def test_app_aliases_route_to_desktop(self, alias):
        with patch("avai.desktop.main", return_value=0) as d:
            rc = main([alias])
        assert rc == 0
        d.assert_called_once_with()


class TestInstallHostsCommand:
    def _registrar(self, outcome):
        from avai.hostsfile import Outcome

        registrar = MagicMock(hosts_path="/etc/hosts")
        registrar.install.return_value = Outcome[outcome]
        registrar.remove.return_value = Outcome[outcome]
        return registrar

    def _run(self, argv, registrar):
        with patch(
            "avai.hostsfile.HostsRegistrar.for_current_platform",
            return_value=registrar,
        ):
            return main(["install-hosts", *argv])

    def test_install_maps_the_default_hostname(self, capsys):
        registrar = self._registrar("CREATED")
        rc = self._run([], registrar)
        assert rc == 0
        registrar.install.assert_called_once_with("avai.local")
        registrar.remove.assert_not_called()
        assert "mapped avai.local" in capsys.readouterr().out

    def test_remove_with_a_custom_hostname(self, capsys):
        registrar = self._registrar("REMOVED")
        rc = self._run(["--remove", "--hostname", "box.local"], registrar)
        assert rc == 0
        registrar.remove.assert_called_once_with("box.local")
        assert "removed box.local" in capsys.readouterr().out

    def test_unchanged_says_so(self, capsys):
        rc = self._run(["--remove"], self._registrar("UNCHANGED"))
        assert rc == 0
        assert "already absent" in capsys.readouterr().out

    def test_permission_error_prints_the_hint(self, capsys):
        from pathlib import Path

        from avai.hostsfile import HostsPermissionError

        registrar = self._registrar("CREATED")
        registrar.install.side_effect = HostsPermissionError(
            Path("/etc/hosts"), "run with sudo"
        )
        rc = self._run([], registrar)
        assert rc == 1
        assert capsys.readouterr().err.strip() == "avai: run with sudo"

    def test_other_hosts_error_is_reported(self, capsys):
        from avai.hostsfile import HostsError

        with patch(
            "avai.hostsfile.HostsRegistrar.for_current_platform",
            side_effect=HostsError("no hosts file here"),
        ):
            rc = main(["install-hosts"])
        assert rc == 1
        assert capsys.readouterr().err.strip() == "avai: no hosts file here"


class TestMigrateCommand:
    def test_migrate_upgrades_the_given_db(self, capsys):
        with patch("avai.db_migrate.upgrade_to_head") as up:
            rc = main(["migrate", "--db", "/tmp/x.db"])
        assert rc == 0
        up.assert_called_once_with("sqlite:////tmp/x.db")
        assert "migrations applied to /tmp/x.db" in capsys.readouterr().out


class TestRulesCommand:
    def _rules_dir(self, tmp_path):
        d = tmp_path / "rules"
        d.mkdir()
        (d / "r.yar").write_text(
            'rule demo_rule : DEMO { strings: $a = "x" condition: $a }'
        )
        return d

    def test_rules_reports_count(self, tmp_path, capsys):
        rc = main(["rules", "--rules-dir", str(self._rules_dir(tmp_path))])
        out = capsys.readouterr().out
        assert rc == 0
        assert "1 YARA rule(s) loaded" in out

    def test_rules_list_prints_identifiers(self, tmp_path, capsys):
        rc = main(["rules", "--rules-dir", str(self._rules_dir(tmp_path)), "--list"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "demo_rule" in out
        assert "[DEMO]" in out  # tag rendered

    def test_rules_empty_dir_returns_1(self, tmp_path, capsys):
        empty = tmp_path / "empty"
        empty.mkdir()
        rc = main(["rules", "--rules-dir", str(empty)])
        assert rc == 1
        assert "no compilable YARA rules" in capsys.readouterr().err


class TestUnknownCommand:
    def test_unknown_returns_exit_2_and_writes_to_stderr(self, capsys):
        rc = main(["bogus-command"])
        err = capsys.readouterr().err
        assert rc == 2
        assert "unknown command" in err
        assert "avai monitor" in err  # usage echoed on stderr


class TestDefaultArgs:
    """Bare `avai monitor` / `avai dashboard` must apply the canonical
    defaults (~/.avai/avai.db etc.) with no flags."""

    def test_monitor_defaults(self):
        from pathlib import Path

        from avai.host_monitor import _build_parser

        ns = _build_parser().parse_args([])
        assert ns.db == str(Path.home() / ".avai" / "avai.db")
        assert ns.interval == 300
        assert ns.judge_max_per_collector == 25

    def test_dashboard_defaults(self):
        from pathlib import Path

        from avai.dashboard import _build_parser

        ns = _build_parser().parse_args([])
        assert ns.db == str(Path.home() / ".avai" / "avai.db")
        assert ns.port == 8765


class TestDashboardServer:
    """The dashboard runs on the waitress production server by default
    (no Werkzeug 'development server' warning); --debug uses app.run."""

    def test_default_serves_via_waitress(self):
        import avai.dashboard as d

        app = MagicMock()
        with patch("waitress.serve") as wserve:
            d._serve(app, "127.0.0.1", 8765, debug=False)
        wserve.assert_called_once()
        assert wserve.call_args.args[0] is app
        app.run.assert_not_called()

    def test_debug_uses_dev_server(self):
        import avai.dashboard as d

        app = MagicMock()
        with patch("waitress.serve") as wserve:
            d._serve(app, "127.0.0.1", 8765, debug=True)
        app.run.assert_called_once()
        wserve.assert_not_called()
