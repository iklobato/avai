"""CLI entrypoint and WSGI launcher for `avai dashboard`."""

from __future__ import annotations

import argparse
import errno
import sys
import threading
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

import waitress
from flask import Flask
from sqlalchemy import create_engine

from avai.host_monitor import Sink
from avai.hostsfile import DASHBOARD_HOSTNAME, HostsError, HostsRegistrar, Outcome

from .app import DashboardApp
from .config import DEFAULT_DB_PATH, DashboardConfig

DEFAULT_PORT = 8765
# Below this, binding a TCP port needs root/Administrator. Reaching the
# dashboard at http://avai.local (no port) means serving on 80, which is
# privileged, so a clean-bind failure here gets an actionable message.
PRIVILEGED_PORT_CEILING = 1024
DEFAULT_HTTP_PORT = 80


class DashboardUrl:
    def http(self, host: str, port: int) -> str:
        """A browser URL, omitting the port when it's the implicit HTTP 80, so
        ``--port 80`` advertises ``http://avai.local`` rather than ``...:80``."""
        if port == DEFAULT_HTTP_PORT:
            return f"http://{host}"
        return f"http://{host}:{port}"


class DashboardArgs:
    def parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description="avai: read-only Flask + HTMX dashboard for the host monitor DB"
        )
        # Bare `avai dashboard` reads ~/.avai/avai.db on :8765 (the monitor's
        # defaults) so it works without flags.
        parser.add_argument("--db", default=str(DEFAULT_DB_PATH))
        parser.add_argument("--host", default="127.0.0.1")
        parser.add_argument("--port", type=int, default=DEFAULT_PORT)
        parser.add_argument("--debug", action="store_true")
        parser.add_argument(
            "--open",
            action="store_true",
            help="open the dashboard in your default browser once it's serving",
        )
        return parser


class DashboardSchema:
    """Bring the dashboard's DB up to the current schema, on every start.

    The dashboard opens the DB read-only, so it can't create or migrate
    tables at query time; the monitor's own bootstrap (``Sink.setup`` =
    ``create_all`` + Alembic upgrade) runs here instead. Not gated on "file
    missing": ``create_all`` only creates absent tables and never touches
    existing data, so a DB written by an OLDER monitor gains the new tables
    (e.g. ``control_state``) instead of every panel 500ing. Reusing
    ``Sink.setup`` keeps the two bootstraps in lockstep, and a dashboard
    started before the monitor ever ran renders empty panels."""

    def ensure(self, db_path: str) -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(f"sqlite:///{db_path}")
        try:
            Sink.create(engine).setup()
        finally:
            engine.dispose()


@dataclass(frozen=True)
class ServeOptions:
    host: str
    port: int
    debug: bool = False
    open_browser: bool = False


class DashboardServer:
    """Serves the dashboard on waitress, a pure-Python production WSGI server
    (no "development server" warning); ``--debug`` uses Werkzeug's reloader
    and debugger instead."""

    # ~10 HTMX fragments fire in parallel on every page load/poll; 16 threads
    # absorbs that burst without queuing.
    THREADS = 16
    BROWSER_DELAY_S = 1.0

    def __init__(self, app: Flask, out: TextIO) -> None:
        self._app = app
        self._out = out

    def serve(self, options: ServeOptions) -> None:
        if options.open_browser:
            self._open_browser(options)
        for line in self._hosts_notice(options.port):
            self._say(line)
        try:
            self._run(options)
        except OSError as exc:
            raise SystemExit(self.bind_error_message(options, exc)) from exc

    def _run(self, options: ServeOptions) -> None:
        if options.debug:
            self._app.run(host=options.host, port=options.port, debug=True)
            return
        url = DashboardUrl().http(options.host, options.port)
        self._say(f" * avai dashboard on {url}  (Ctrl-C to quit)")
        waitress.serve(
            self._app, host=options.host, port=options.port, threads=self.THREADS
        )

    def _open_browser(self, options: ServeOptions) -> None:
        """Open the dashboard after a short delay so the server has bound the
        socket. 0.0.0.0/:: aren't routable from a browser: use loopback."""
        host = "127.0.0.1" if options.host in ("0.0.0.0", "::", "") else options.host
        url = DashboardUrl().http(host, options.port)
        threading.Timer(self.BROWSER_DELAY_S, webbrowser.open, args=(url,)).start()

    def _hosts_notice(self, port: int) -> list[str]:
        """Map avai.local when already elevated, otherwise say how. A
        hosts-file problem must never stop the dashboard serving on
        loopback, so any of it degrades to a quiet line."""
        try:
            outcome = HostsRegistrar.for_current_platform().ensure_reachable()
        except HostsError:
            return []
        url = DashboardUrl().http(DASHBOARD_HOSTNAME, port)
        notices = {
            Outcome.CREATED: f" * mapped {DASHBOARD_HOSTNAME} -> 127.0.0.1 — also reachable at {url}",
            Outcome.NEEDS_PRIVILEGE: f" * tip: `sudo avai install-hosts` makes the dashboard reachable at {url}",
        }
        return [notices.get(outcome, f" * also reachable at {url}")]

    def bind_error_message(self, options: ServeOptions, err: OSError) -> str:
        """One actionable line for a socket-bind failure. The common case is
        forgetting that http://avai.local (port 80) needs privilege."""
        host, port = options.host, options.port
        denied = err.errno in (errno.EACCES, errno.EPERM)
        if denied and port < PRIVILEGED_PORT_CEILING:
            return (
                f"avai: binding port {port} needs elevated privileges — "
                f"re-run with `sudo avai dashboard --port {port}`, or use the "
                "default unprivileged port (`avai dashboard`)."
            )
        if err.errno == errno.EADDRINUSE:
            return f"avai: port {port} on {host} is already in use by another process."
        return f"avai: could not bind {host}:{port}: {err}"

    def _say(self, line: str) -> None:
        self._out.write(line + "\n")
        self._out.flush()


class DashboardCli:
    @classmethod
    def main(cls) -> int:
        args = DashboardArgs().parser().parse_args()
        DashboardSchema().ensure(args.db)
        app = DashboardApp(DashboardConfig.from_env(args.db)).build()
        options = ServeOptions(args.host, args.port, args.debug, args.open)
        DashboardServer(app, sys.stdout).serve(options)
        return 0


if __name__ == "__main__":
    sys.exit(DashboardCli.main())
