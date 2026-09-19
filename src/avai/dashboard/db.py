"""The dashboard's two SQLite engines, built once per app: a read-only one
for every panel, and a writable one for the control row and feedback."""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Optional

from flask import has_request_context, request
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine

_LOGGED_PARAMS_MAX = 300


def read_only_engine(db_path: str, query_log_path: Optional[str] = None) -> Engine:
    """One pooled engine per app, reused by every request. An engine per
    request leaked SQLite connections and file handles under the dozen HTMX
    fragments that poll concurrently, and saturated the WSGI worker threads.

    We open read-only (``mode=ro``) and deliberately do NOT pass
    ``immutable=1``: ``immutable=1`` tells SQLite to ignore the ``-wal``
    file, so on a live DB the monitor is writing (especially before the
    first WAL checkpoint) the reader would see an empty/incomplete
    database and every query would 500 with "no such table". ``mode=ro``
    reads the WAL correctly, so the dashboard sees live data immediately;
    a fresh read transaction per query still picks up newly committed
    rows. ``check_same_thread=False`` is required because waitress hands
    pooled connections to different worker threads.
    """
    engine = create_engine(
        f"sqlite:///file:{db_path}?mode=ro&uri=true",
        connect_args={"check_same_thread": False},
    )
    if query_log_path:
        event.listen(engine, "before_cursor_execute", _QueryLog(query_log_path))
    return engine


def writable_engine(db_path: str) -> Engine:
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    event.listen(engine, "connect", _on_connect)
    return engine


def _on_connect(dbapi_conn, _record):
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    # Wait (up to 5s) for the monitor's write lock instead of raising
    # "database is locked": control writes are tiny, contention is rare.
    cur.execute("PRAGMA busy_timeout=5000")
    cur.close()


class _QueryLog:
    """SQLAlchemy before_cursor_execute hook: append one line per query."""

    def __init__(self, path: str):
        self._path = path
        self._lock = threading.Lock()

    def __call__(self, _conn, _cursor, statement, parameters, *_context):
        route = request.path if has_request_context() else "-"
        sql = " ".join(str(statement).split())
        params = str(parameters)
        if len(params) > _LOGGED_PARAMS_MAX:
            params = params[:_LOGGED_PARAMS_MAX] + "…"
        line = (
            f"{datetime.now(timezone.utc).isoformat(timespec='seconds')}\t"
            f"{route}\t{sql}\t{params}\n"
        )
        with self._lock:
            try:
                with open(self._path, "a") as fh:
                    fh.write(line)
            except OSError:
                pass
