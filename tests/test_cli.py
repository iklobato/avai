"""CLI dispatcher tests.

Covers the subcommand routing in :mod:`avai.cli` and the version /
help short-circuits — without touching ``host_monitor`` or
``dashboard`` (their ``main`` functions are mocked).
"""

from __future__ import annotations

from unittest.mock import patch

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

    def test_remaining_argv_passed_through(self):
        """sys.argv is rewritten so the called main() sees only its
        own arguments — the original `monitor` token is dropped."""
        import sys

        captured: list[str] = []

        def fake_main():
            captured.extend(sys.argv)
            return 0

        with patch("avai.host_monitor.main", side_effect=fake_main):
            main(["monitor", "--once", "--db", "/tmp/x"])

        assert captured[0] == "avai monitor"
        assert captured[1:] == ["--once", "--db", "/tmp/x"]


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

        with patch("waitress.serve") as wserve, patch.object(d.app, "run") as arun:
            d._serve("127.0.0.1", 8765, debug=False)
        wserve.assert_called_once()
        arun.assert_not_called()

    def test_debug_uses_dev_server(self):
        import avai.dashboard as d

        with patch("waitress.serve") as wserve, patch.object(d.app, "run") as arun:
            d._serve("127.0.0.1", 8765, debug=True)
        arun.assert_called_once()
        wserve.assert_not_called()
