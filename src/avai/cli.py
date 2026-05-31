"""avai CLI — subcommand dispatcher.

Installed as the ``avai`` console_script. Routes ``avai monitor ...``
to :func:`avai.host_monitor.main` and ``avai dashboard ...`` to
:func:`avai.dashboard.main`. Each subcommand passes its remaining
argv through unchanged.
"""

from __future__ import annotations

import sys
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

  avai --version              print the installed package version
  avai --help                 this message
"""


def _print_usage(stream=None) -> None:
    print(_USAGE, file=stream or sys.stdout)


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
