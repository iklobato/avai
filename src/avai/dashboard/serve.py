"""CLI entrypoint and WSGI launcher for `avai dashboard`."""

from __future__ import annotations

import argparse
import sys
import threading
import webbrowser
from pathlib import Path

from sqlalchemy import create_engine


from .app import app
from .queries import DEFAULT_DB_PATH


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
    threading.Timer(1.0, lambda: webbrowser.open(f"http://{url_host}:{port}")).start()


def _serve(host: str, port: int, debug: bool, open_browser: bool = False) -> None:
    """Serve the dashboard. In normal use we run on waitress, a real
    (pure-Python, cross-platform) WSGI server, so there's no "this is a
    development server" warning. ``--debug`` falls back to Werkzeug's
    reloader/debugger (dev only), and if waitress somehow isn't installed
    we degrade to the dev server rather than failing to start."""
    if open_browser:
        _open_browser(host, port)
    if not debug:
        try:
            from waitress import serve

            print(
                f" * avai dashboard on http://{host}:{port}  (Ctrl-C to quit)",
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
