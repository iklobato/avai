"""Writable control-plane access for the dashboard.

Kept separate from the read-only ``queries`` layer: ``queries._engine`` caches a
strictly read-only engine (``mode=ro``); control needs a writable one. The
dashboard's ONLY writes are to the single ``control_state`` row — the monitor
stays the sole writer of telemetry. WAL + a ``busy_timeout`` keep the two
processes from colliding on that one row (writes are tiny and rare).
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone

from flask import current_app
from sqlalchemy import create_engine, event, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from avai.host_monitor import ControlState

_write_engine_cache: dict[str, object] = {}
_write_engine_lock = threading.Lock()


def _on_connect(dbapi_conn, _record):
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    # Wait (up to 5s) for the monitor's write lock instead of raising
    # "database is locked" — control writes are tiny, contention is rare.
    cur.execute("PRAGMA busy_timeout=5000")
    cur.close()


def _write_engine():
    db_path = current_app.config["DB_PATH"]
    eng = _write_engine_cache.get(db_path)
    if eng is None:
        with _write_engine_lock:
            eng = _write_engine_cache.get(db_path)
            if eng is None:
                eng = create_engine(
                    f"sqlite:///{db_path}",
                    connect_args={"check_same_thread": False},
                )
                event.listen(eng, "connect", _on_connect)
                _write_engine_cache[db_path] = eng
    return eng


def _ensure_row(session) -> None:
    # id=1 only; the model's column defaults populate the NOT NULL counters.
    session.execute(sqlite_insert(ControlState).values(id=1).on_conflict_do_nothing())


def _update(**values) -> None:
    with Session(_write_engine()) as session:
        _ensure_row(session)
        session.execute(
            update(ControlState).where(ControlState.id == 1).values(**values)
        )
        session.commit()


def set_paused(paused: bool) -> None:
    _update(paused=int(paused))


def bump_scan_now() -> None:
    """Request an immediate scan (monitor runs one cycle within a poll tick)."""
    with Session(_write_engine()) as session:
        _ensure_row(session)
        session.execute(
            update(ControlState)
            .where(ControlState.id == 1)
            .values(scan_now_nonce=ControlState.scan_now_nonce + 1)
        )
        session.commit()


def set_settings(*, interval=None, judge=None, enrich=None) -> None:
    values: dict = {}
    if interval is not None:
        values["interval_override"] = int(interval)
    if judge is not None:
        values["judge_enabled"] = int(judge)
    if enrich is not None:
        values["enrich_enabled"] = int(enrich)
    if values:
        _update(**values)


def set_collector(name: str, enabled: bool) -> None:
    with Session(_write_engine()) as session:
        _ensure_row(session)
        row = session.get(ControlState, 1)
        current = {
            s.strip() for s in (row.disabled_collectors or "").split(",") if s.strip()
        }
        current.discard(name) if enabled else current.add(name)
        row.disabled_collectors = ",".join(sorted(current)) or None
        session.commit()


def queue_command(command: str) -> None:
    """Queue a one-shot maintenance command; the monitor runs + acks it."""
    with Session(_write_engine()) as session:
        _ensure_row(session)
        session.execute(
            update(ControlState)
            .where(ControlState.id == 1)
            .values(command=command, command_nonce=ControlState.command_nonce + 1)
        )
        session.commit()


def read_control_state() -> dict | None:
    """Read the control row (read-only engine is fine) for display."""
    from .queries import _session

    with _session() as session:
        row = session.get(ControlState, 1)
        if row is None:
            return None
        return {c.name: getattr(row, c.name) for c in ControlState.__table__.columns}


def monitor_alive(state: dict | None) -> bool:
    """Heartbeat freshness check. The monitor writes last_seen_at every poll
    tick (~3s) even while idle/paused, so a generous 120s window only ever
    reads 'dead' if the process is actually gone (or stuck in a very long
    first-cycle scan, which shows status='scanning' for context)."""
    if not state or not state.get("last_seen_at"):
        return False
    try:
        seen = datetime.fromisoformat(state["last_seen_at"])
    except (TypeError, ValueError):
        return False
    return (datetime.now(timezone.utc) - seen).total_seconds() < 120
