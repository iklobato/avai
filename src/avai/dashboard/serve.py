"""CLI entrypoint and WSGI launcher for `avai dashboard`."""
from __future__ import annotations

import argparse
import sys
import threading
import webbrowser
from pathlib import Path
from sqlalchemy import create_engine
from avai.host_monitor import Base

from .queries import DEFAULT_DB_PATH
from .app import app


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
    """Create an empty schema if the DB file doesn't exist yet.

    The dashboard opens the database read-only with ``immutable=1``,
    which SQLite *refuses* to apply to a non-existent file (the
    immutable flag promises the file won't change — there's no file
    to promise about). Without this, a dashboard launched before the
    monitor has run produces 500s on every query.

    Creating the schema also makes empty-state rendering work: every
    table exists, every query returns zero rows, every panel renders
    empty rather than erroring.
    """
    db_file = Path(db_path)
    if db_file.exists() and db_file.stat().st_size > 0:
        return
    db_file.parent.mkdir(parents=True, exist_ok=True)
    # Register the enrichment model on Base.metadata before create_all,
    # so a dashboard-only deployment (no monitor co-located) still gets
    # the enrichment_evidence table — otherwise any dashboard query
    # against it 500s.
    from avai.enrichers.cache import register_schema

    register_schema(Base)
    write_engine = create_engine(f"sqlite:///{db_path}")
    try:
        Base.metadata.create_all(write_engine)
    finally:
        write_engine.dispose()


if __name__ == "__main__":
    sys.exit(main())
