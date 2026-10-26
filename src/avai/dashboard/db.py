"""The dashboard's two SQLite engines, built once per app: a read-only one
for every panel, and a writable one for the control row and feedback."""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any

from flask import has_request_context, request
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine


class DashboardEngines:
    def read_only(self, db_path: str, query_log_path: str | None = None) -> Engine:
        """One pooled engine per app, reused by every request (an engine per
        request leaked connections under the concurrently polling fragments).

        ``mode=ro`` without ``immutable=1``: ``immutable=1`` makes SQLite
        ignore the ``-wal`` file, so a live DB would read as empty and every
        query would 500. ``mode=ro`` reads the WAL, and a fresh read
        transaction per query still sees newly committed rows.
        ``check_same_thread=False`` because waitress hands pooled
        connections to different worker threads."""
        engine = create_engine(
            f"sqlite:///file:{db_path}?mode=ro&uri=true",
            connect_args={"check_same_thread": False},
        )
        if query_log_path:
            log = QueryLog(query_log_path, threading.Lock())
            event.listen(engine, "connect", log.install)
        return engine

    def writable(self, db_path: str) -> Engine:
        engine = create_engine(
            f"sqlite:///{db_path}", connect_args={"check_same_thread": False}
        )
        event.listen(engine, "connect", WritablePragmas().apply)
        return engine


class WritablePragmas:
    # Wait for the monitor's write lock instead of raising "database is
    # locked": control writes are tiny, contention is rare.
    BUSY_TIMEOUT_MS = 5000

    def apply(self, dbapi_conn: Any, _record: Any) -> None:
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute(f"PRAGMA busy_timeout={self.BUSY_TIMEOUT_MS}")
        cursor.close()


class QueryLog:
    """Append one line per SQL statement the read-only engine runs (a debug
    aid behind ``AVAI_QUERY_LOG``). Hooked through sqlite3's trace callback,
    which hands over the statement with its parameters already bound."""

    def __init__(self, path: str, lock: threading.Lock) -> None:
        self._path = path
        self._lock = lock

    def install(self, dbapi_conn: Any, _record: Any) -> None:
        dbapi_conn.set_trace_callback(self.record)

    def record(self, statement: str) -> None:
        route = request.path if has_request_context() else "-"
        sql = " ".join(statement.split())
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            self._append(f"{stamp}\t{route}\t{sql}\n")

    def _append(self, line: str) -> None:
        try:
            with open(self._path, "a") as handle:
                handle.write(line)
        except OSError:
            return  # query logging is a debug aid; a failed write must not 500
