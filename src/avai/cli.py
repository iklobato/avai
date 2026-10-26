"""avai CLI — subcommand dispatcher.

Installed as the ``avai`` console_script. Routes ``avai monitor ...``
to :meth:`avai.host_monitor.main.MonitorApp.main` and ``avai dashboard ...`` to
:meth:`avai.dashboard.serve.DashboardCli.main`. Each subcommand passes its remaining
argv through unchanged.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from operator import attrgetter
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, TextIO

from . import __version__
from .hostsfile import (
    DASHBOARD_HOSTNAME,
    HostsError,
    HostsPermissionError,
    HostsRegistrar,
    Outcome,
)
from .observability import SentryReporting

if TYPE_CHECKING:
    import yara

USAGE = """avai — host security telemetry collector + dashboard

usage:
  avai monitor [--once] [--interval N] [--db PATH] [...]
                              start the host monitor (collectors + LLM
                              judge). See `avai monitor --help` for
                              every flag.

  avai dashboard [--port N] [--db PATH]
                              start the read-only Flask + HTMX
                              dashboard. See `avai dashboard --help`.

  avai app                    open the desktop app: dashboard + monitor in
                              one native window (needs the GUI extra:
                              pip install 'avai-monitor[app]').

  avai rules [--list]         show the YARA ruleset the file scanner
                              loads (counts; --list prints every rule).

  avai install-hosts [--remove] [--hostname NAME]
                              map avai.local -> 127.0.0.1 in the OS hosts
                              file so the dashboard is reachable by name
                              (needs sudo / Administrator). --remove undoes it.

  avai --version              print the installed package version
  avai --help                 this message
"""

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
HELP_FLAGS = ("-h", "--help", "help")
VERSION_FLAGS = ("-v", "--version")


class Console:
    def __init__(self, out: TextIO, err: TextIO) -> None:
        self._out = out
        self._err = err

    def say(self, line: str) -> None:
        self._out.write(line + "\n")

    def warn(self, line: str) -> None:
        self._err.write(line + "\n")


class Command(Protocol):
    def execute(self, rest: list[str]) -> int:
        """Run with the argv that follows the subcommand name."""
        ...


# Imports stay inside the commands so `avai --version` doesn't load the
# monitor or the dashboard.
class MonitorCommand:
    def execute(self, rest: list[str]) -> int:
        from .host_monitor.main import MonitorApp

        sys.argv = ["avai monitor", *rest]
        return MonitorApp.main()


class DashboardCommand:
    def execute(self, rest: list[str]) -> int:
        from .dashboard.serve import DashboardCli

        sys.argv = ["avai dashboard", *rest]
        return DashboardCli.main()


class DesktopCommand:
    def execute(self, rest: list[str]) -> int:
        from .desktop import DesktopApp

        return DesktopApp.main()


class RulesCommand:
    """Compile the file-scanner ruleset and report what loaded: the
    user-facing answer to 'which rules are available?'. Read-only; no DB."""

    def __init__(self, console: Console) -> None:
        self._console = console

    def execute(self, rest: list[str]) -> int:
        from .host_monitor.collectors import YaraRulesetCompiler
        from .host_monitor.constants import LOGGER_NAME, YARA_RULES_DIR

        args = self._parser(YARA_RULES_DIR).parse_args(rest)
        rules_dir = Path(args.rules_dir)
        compiler = YaraRulesetCompiler(rules_dir, logging.getLogger(LOGGER_NAME))
        rules, _stats = compiler.compile()
        if rules is None:
            self._console.warn(f"avai: no compilable YARA rules under {rules_dir}")
            return EXIT_FAILURE
        loaded = sorted(rules, key=attrgetter("identifier"))
        self._console.say(f"avai: {len(loaded)} YARA rule(s) loaded from {rules_dir}")
        if args.list:
            self._list(loaded)
            return EXIT_OK
        self._console.say("  (run with --list to print every rule identifier)")
        return EXIT_OK

    def _list(self, loaded: list[yara.Rule]) -> None:
        for rule in loaded:
            tags = " ".join(rule.tags)
            self._console.say(f"  {rule.identifier}" + (f"  [{tags}]" if tags else ""))

    def _parser(self, default_dir: Path) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="avai rules",
            description="Inspect the YARA ruleset the file scanner loads.",
        )
        parser.add_argument(
            "--rules-dir",
            default=str(default_dir),
            help="rules directory to compile (default: bundled + vendor packs)",
        )
        parser.add_argument(
            "--list", action="store_true", help="print every loaded rule identifier"
        )
        return parser


class HostsCommand:
    """Add/remove the ``hostname -> 127.0.0.1`` mapping in the OS hosts file.
    Privileged + platform-specific work lives in :mod:`avai.hostsfile`; here we
    just translate its typed errors into a friendly message + exit code."""

    def __init__(self, console: Console) -> None:
        self._console = console

    def execute(self, rest: list[str]) -> int:
        args = self._parser().parse_args(rest)
        try:
            registrar = HostsRegistrar.for_current_platform()
            outcome = self._apply(registrar, args)
        except HostsPermissionError as err:
            self._console.warn(f"avai: {err.hint}")
            return EXIT_FAILURE
        except HostsError as err:
            self._console.warn(f"avai: {err}")
            return EXIT_FAILURE
        self._console.say(self._notice(registrar, args)[outcome])
        return EXIT_OK

    def _apply(self, registrar: HostsRegistrar, args: argparse.Namespace) -> Outcome:
        if args.remove:
            return registrar.remove(args.hostname)
        return registrar.install(args.hostname)

    def _notice(
        self, registrar: HostsRegistrar, args: argparse.Namespace
    ) -> dict[Outcome, str]:
        hostname, path = args.hostname, registrar.hosts_path
        state = "absent" if args.remove else "mapped"
        return {
            Outcome.CREATED: f"avai: mapped {hostname} -> loopback (IPv4 + IPv6) in {path}",
            Outcome.REMOVED: f"avai: removed {hostname} from {path}",
            Outcome.UNCHANGED: f"avai: {hostname} already {state} - no change",
        }

    def _parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="avai install-hosts",
            description="Map a hostname (default avai.local) to 127.0.0.1 in the "
            "OS hosts file so the dashboard is reachable by name.",
        )
        parser.add_argument("--hostname", default=DASHBOARD_HOSTNAME)
        parser.add_argument(
            "--remove",
            action="store_true",
            help="remove the mapping instead of adding it",
        )
        return parser


class MigrateCommand:
    def __init__(self, console: Console) -> None:
        self._console = console

    def execute(self, rest: list[str]) -> int:
        from .db_migrate import AlembicMigrator
        from .host_monitor import DEFAULT_DB_PATH

        parser = argparse.ArgumentParser(prog="avai migrate")
        parser.add_argument("--db", default=str(DEFAULT_DB_PATH))
        args = parser.parse_args(rest)
        AlembicMigrator(f"sqlite:///{args.db}").upgrade_to_head()
        self._console.say(f"avai: migrations applied to {args.db}")
        return EXIT_OK


class AvaiCli:
    """Routes ``avai <subcommand> ...``; each subcommand gets the argv after
    its own name."""

    def __init__(self, console: Console) -> None:
        self._console = console

    @classmethod
    def main(cls, argv: list[str] | None = None) -> int:
        SentryReporting(os.environ).init()
        cli = cls(Console(sys.stdout, sys.stderr))
        return cli.dispatch(sys.argv[1:] if argv is None else argv)

    def dispatch(self, argv: list[str]) -> int:
        if not argv or argv[0] in HELP_FLAGS:
            self._console.say(USAGE)
            return EXIT_OK
        if argv[0] in VERSION_FLAGS:
            self._console.say(__version__)
            return EXIT_OK
        command = self._commands().get(argv[0])
        if command is None:
            self._console.warn(f"avai: unknown command '{argv[0]}'\n")
            self._console.warn(USAGE)
            return EXIT_USAGE
        return command.execute(argv[1:])

    def _commands(self) -> dict[str, Command]:
        monitor, dashboard, desktop = (
            MonitorCommand(),
            DashboardCommand(),
            DesktopCommand(),
        )
        return {
            "monitor": monitor,
            "start": monitor,
            "scan": monitor,
            "dashboard": dashboard,
            "ui": dashboard,
            "serve": dashboard,
            "app": desktop,
            "gui": desktop,
            "desktop": desktop,
            "rules": RulesCommand(self._console),
            "install-hosts": HostsCommand(self._console),
            "migrate": MigrateCommand(self._console),
        }


if __name__ == "__main__":
    sys.exit(AvaiCli.main())
