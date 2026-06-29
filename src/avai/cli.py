"""avai CLI — subcommand dispatcher.

Installed as the ``avai`` console_script. Routes ``avai monitor ...``
to :func:`avai.host_monitor.main` and ``avai dashboard ...`` to
:func:`avai.dashboard.main`. Each subcommand passes its remaining
argv through unchanged.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

_USAGE = """avai — host security telemetry collector + dashboard

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


def _print_usage(stream=None) -> None:
    print(_USAGE, file=stream or sys.stdout)


def _cmd_rules(rules_dir: Path, do_list: bool) -> int:
    """Compile the file-scanner ruleset and report what loaded — the
    user-facing answer to 'which rules are available?'. Read-only; no DB."""
    from .host_monitor.collectors import _compile_yara_rules

    rules, _stats = _compile_yara_rules(rules_dir)
    if rules is None:
        print(f"avai: no compilable YARA rules under {rules_dir}", file=sys.stderr)
        return 1
    loaded = list(rules)
    print(f"avai: {len(loaded)} YARA rule(s) loaded from {rules_dir}")
    if do_list:
        for r in sorted(loaded, key=lambda x: x.identifier):
            tags = " ".join(r.tags)
            print(f"  {r.identifier}" + (f"  [{tags}]" if tags else ""))
    else:
        print("  (run with --list to print every rule identifier)")
    return 0


def _cmd_install_hosts(hostname: str, remove: bool) -> int:
    """Add/remove the ``hostname -> 127.0.0.1`` mapping in the OS hosts file.
    Privileged + platform-specific work lives in :mod:`avai.hostsfile`; here we
    just translate its typed errors into a friendly message + exit code."""
    from .hostsfile import HostsError, HostsPermissionError, HostsRegistrar, Outcome

    try:
        registrar = HostsRegistrar.for_current_platform()
        outcome = registrar.remove(hostname) if remove else registrar.install(hostname)
    except HostsPermissionError as e:
        print(f"avai: {e.hint}", file=sys.stderr)
        return 1
    except HostsError as e:
        print(f"avai: {e}", file=sys.stderr)
        return 1

    notices = {
        Outcome.CREATED: f"avai: mapped {hostname} -> loopback (IPv4 + IPv6) in {registrar.hosts_path}",
        Outcome.REMOVED: f"avai: removed {hostname} from {registrar.hosts_path}",
        Outcome.UNCHANGED: f"avai: {hostname} already "
        + ("absent" if remove else "mapped")
        + " — no change",
    }
    print(notices[outcome])
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if not argv or argv[0] in ("-h", "--help", "help"):
        _print_usage()
        return 0

    if argv[0] in ("-v", "--version"):
        from . import __version__

        print(__version__)
        return 0

    cmd, rest = argv[0], argv[1:]

    if cmd in ("monitor", "start", "scan"):
        from .host_monitor import main as monitor_main

        sys.argv = ["avai monitor", *rest]
        return monitor_main()

    if cmd in ("dashboard", "ui", "serve"):
        from .dashboard import main as dashboard_main

        sys.argv = ["avai dashboard", *rest]
        return dashboard_main()

    if cmd in ("app", "gui", "desktop"):
        from .desktop import main as desktop_main

        return desktop_main()

    if cmd == "rules":
        import argparse

        from .host_monitor import constants

        p = argparse.ArgumentParser(
            prog="avai rules",
            description="Inspect the YARA ruleset the file scanner loads.",
        )
        p.add_argument(
            "--rules-dir",
            default=str(constants.YARA_RULES_DIR),
            help="rules directory to compile (default: bundled + vendor packs)",
        )
        p.add_argument(
            "--list", action="store_true", help="print every loaded rule identifier"
        )
        a = p.parse_args(rest)
        return _cmd_rules(Path(a.rules_dir), a.list)

    if cmd == "install-hosts":
        import argparse

        from .hostsfile import DASHBOARD_HOSTNAME

        p = argparse.ArgumentParser(
            prog="avai install-hosts",
            description="Map a hostname (default avai.local) to 127.0.0.1 in the "
            "OS hosts file so the dashboard is reachable by name.",
        )
        p.add_argument("--hostname", default=DASHBOARD_HOSTNAME)
        p.add_argument(
            "--remove",
            action="store_true",
            help="remove the mapping instead of adding it",
        )
        a = p.parse_args(rest)
        return _cmd_install_hosts(a.hostname, a.remove)

    if cmd == "migrate":
        import argparse

        from .db_migrate import upgrade_to_head
        from .host_monitor import DEFAULT_DB_PATH

        p = argparse.ArgumentParser(prog="avai migrate")
        p.add_argument("--db", default=str(DEFAULT_DB_PATH))
        a = p.parse_args(rest)
        upgrade_to_head(f"sqlite:///{a.db}")
        print(f"avai: migrations applied to {a.db}")
        return 0

    print(f"avai: unknown command '{cmd}'\n", file=sys.stderr)
    _print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
