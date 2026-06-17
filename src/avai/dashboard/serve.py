"""CLI entrypoint and WSGI launcher for `avai dashboard`."""

from __future__ import annotations

import argparse
import errno
import sys
import threading
import webbrowser
from pathlib import Path

from sqlalchemy import create_engine

from .app import app
from .queries import DEFAULT_DB_PATH

# Below this, binding a TCP port needs root/Administrator. Reaching the
# dashboard at http://avai.local (no port) means serving on 80, which is
# privileged — so a clean-bind failure here gets an actionable message.
_PRIVILEGED_PORT_CEILING = 1024
_DEFAULT_HTTP_PORT = 80


def _http_url(host: str, port: int) -> str:
    """A browser URL, omitting the port when it's the implicit HTTP 80 — so
    ``--port 80`` advertises ``http://avai.local`` rather than ``...:80``."""
    return f"http://{host}" if port == _DEFAULT_HTTP_PORT else f"http://{host}:{port}"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="avai — read-only Flask + HTMX dashboard for the host monitor DB"
    )
    # Bare `avai dashboard` reads ~/.avai/avai.db on :8765 (the monitor's
    # defaults) so it Just Works without flags.
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument(
        "--open",
        action="store_true",
        help="open the dashboard in your default browser once it's serving",
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()

    app.config["DB_PATH"] = args.db
    _ensure_db_exists(args.db)
    _serve(args.host, args.port, args.debug, args.open)
    return 0


def _open_browser(host: str, port: int) -> None:
    """Open the dashboard in the default browser after a short delay so the
    server has time to bind the socket. 0.0.0.0/:: aren't routable from a
    browser, so point at loopback instead."""
    url_host = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
    url = _http_url(url_host, port)
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()


def _hosts_notice(port: int) -> list[str]:
    """Best-effort hostname mapping for the launch banner: map avai.local when
    the dashboard already runs elevated, otherwise tell the user how. A
    hosts-file problem (unsupported OS, missing privilege) must never stop the
    dashboard from serving on loopback, so all of it degrades to a quiet line."""
    from avai.hostsfile import DASHBOARD_HOSTNAME, HostsError, HostsRegistrar, Outcome

    try:
        registrar = HostsRegistrar.for_current_platform()
        outcome = registrar.ensure_reachable()
    except HostsError:
        return []
    url = _http_url(DASHBOARD_HOSTNAME, port)
    if outcome is Outcome.CREATED:
        return [
            f" * mapped {DASHBOARD_HOSTNAME} -> 127.0.0.1 — also reachable at {url}"
        ]
    if outcome is Outcome.NEEDS_PRIVILEGE:
        return [
            f" * tip: `sudo avai install-hosts` makes the dashboard reachable at {url}"
        ]
    return [f" * also reachable at {url}"]


def _serve(host: str, port: int, debug: bool, open_browser: bool = False) -> None:
    """Serve the dashboard. In normal use we run on waitress, a real
    (pure-Python, cross-platform) WSGI server, so there's no "this is a
    development server" warning. ``--debug`` falls back to Werkzeug's
    reloader/debugger (dev only), and if waitress somehow isn't installed
    we degrade to the dev server rather than failing to start."""
    if open_browser:
        _open_browser(host, port)
    for line in _hosts_notice(port):
        print(line, flush=True)
    try:
        _run_server(host, port, debug)
    except OSError as e:
        raise SystemExit(_bind_error_message(host, port, e)) from e


def _run_server(host: str, port: int, debug: bool) -> None:
    if not debug:
        try:
            from waitress import serve

            print(
                f" * avai dashboard on {_http_url(host, port)}  (Ctrl-C to quit)",
                flush=True,
            )
            # ~10 HTMX fragments fire in parallel on every page load/poll
            # (7 × every-30s + 3 × every-60s + JS alerts). 16 threads absorbs
            # that burst without queuing; extras sit idle otherwise.
            serve(app, host=host, port=port, threads=16)
            return
        except ImportError:
            print(
                " * waitress not installed — falling back to the dev server",
                file=sys.stderr,
            )
    app.run(host=host, port=port, debug=debug)


def _bind_error_message(host: str, port: int, err: OSError) -> str:
    """Turn a socket-bind failure into one actionable line. The common case is
    forgetting that http://avai.local (port 80) needs privilege to bind."""
    if err.errno in (errno.EACCES, errno.EPERM) and port < _PRIVILEGED_PORT_CEILING:
        return (
            f"avai: binding port {port} needs elevated privileges — "
            f"re-run with `sudo avai dashboard --port {port}`, or use the "
            "default unprivileged port (`avai dashboard`)."
        )
    if err.errno == errno.EADDRINUSE:
        return f"avai: port {port} on {host} is already in use by another process."
    return f"avai: could not bind {host}:{port}: {err}"


def _ensure_db_exists(db_path: str) -> None:
    """Bring the dashboard's DB up to the current schema, on every start.

    The dashboard opens the DB read-only and so can't create or migrate
    tables at query time. We run the monitor's own schema bootstrap
    (:meth:`Sink.setup` = ``create_all`` + Alembic upgrade) here instead.
    Crucially this is NOT gated on "file missing": ``create_all`` only
    issues ``CREATE TABLE`` for tables that don't exist yet and never
    touches existing data, so running it against a DB written by an OLDER
    monitor — one lacking a newly-added table such as ``control_state`` —
    simply adds the missing table. That's what stops every panel 500ing
    after a version that introduces a new table. Reusing ``Sink.setup``
    keeps the dashboard's schema bootstrap in lockstep with the monitor's
    (one source of truth), so future tables/migrations are covered too.

    It also lets a dashboard launched before the monitor has ever run
    render empty panels (every table exists, every query returns zero rows).
    """
    from avai.host_monitor import Sink

    db_file = Path(db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    write_engine = create_engine(f"sqlite:///{db_path}")
    try:
        Sink(write_engine).setup()
    finally:
        write_engine.dispose()


if __name__ == "__main__":
    sys.exit(main())
