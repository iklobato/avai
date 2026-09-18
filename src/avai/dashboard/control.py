"""Writable control-plane access for the dashboard.

Kept separate from the read-only ``queries`` layer, which only ever gets a
strictly read-only engine (``mode=ro``); control needs a writable one. The
dashboard's ONLY writes are to the single ``control_state`` row and to
operator feedback: the monitor stays the sole writer of telemetry. WAL + a
``busy_timeout`` keep the two processes from colliding on that one row
(writes are tiny and rare).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from avai.host_monitor import ControlState, FeedbackRow
from avai.host_monitor.constants import MONITOR_LIVENESS_WINDOW_S


def _ensure_row(session) -> None:
    # id=1 only; the model's column defaults populate the NOT NULL counters.
    session.execute(sqlite_insert(ControlState).values(id=1).on_conflict_do_nothing())


class ControlStore:
    """The dashboard's writes, through one writable engine per app."""

    def __init__(self, engine: Engine):
        self._engine = engine

    def _update(self, **values) -> None:
        with Session(self._engine) as session:
            _ensure_row(session)
            session.execute(
                update(ControlState).where(ControlState.id == 1).values(**values)
            )
            session.commit()

    def set_paused(self, paused: bool) -> None:
        self._update(paused=int(paused))

    def bump_scan_now(self) -> None:
        """Request an immediate scan (monitor runs one cycle within a poll tick)."""
        with Session(self._engine) as session:
            _ensure_row(session)
            session.execute(
                update(ControlState)
                .where(ControlState.id == 1)
                .values(scan_now_nonce=ControlState.scan_now_nonce + 1)
            )
            session.commit()

    def set_settings(self, *, interval=None, judge=None, enrich=None) -> None:
        values: dict = {}
        if interval is not None:
            values["interval_override"] = int(interval)
        if judge is not None:
            values["judge_enabled"] = int(judge)
        if enrich is not None:
            values["enrich_enabled"] = int(enrich)
        if values:
            self._update(**values)

    def set_collector(self, name: str, enabled: bool) -> None:
        with Session(self._engine) as session:
            _ensure_row(session)
            row = session.get(ControlState, 1)
            current = {
                s.strip()
                for s in (row.disabled_collectors or "").split(",")
                if s.strip()
            }
            current.discard(name) if enabled else current.add(name)
            row.disabled_collectors = ",".join(sorted(current)) or None
            session.commit()

    def record_feedback(
        self,
        *,
        content_hash: str,
        collector: str,
        label: str,
        note: str | None,
        artifact: str | None,
    ) -> None:
        """Persist an operator correction on a finding (latest-wins per finding).
        The monitor picks it up next cycle: it applies it to the verdict and feeds
        it back to the judge. This is the one telemetry-adjacent table the
        dashboard writes; the monitor remains the sole writer of findings."""
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with Session(self._engine) as session:
            session.execute(
                sqlite_insert(FeedbackRow)
                .values(
                    content_hash=content_hash,
                    collector=collector,
                    label=label,
                    note=note,
                    artifact=artifact,
                    created_at=now,
                    applied=0,
                )
                .on_conflict_do_update(
                    index_elements=["content_hash", "collector"],
                    set_={
                        "label": label,
                        "note": note,
                        "artifact": artifact,
                        "created_at": now,
                        "applied": 0,
                    },
                )
            )
            session.commit()

    def queue_command(self, command: str) -> None:
        """Queue a one-shot maintenance command; the monitor runs + acks it."""
        with Session(self._engine) as session:
            _ensure_row(session)
            session.execute(
                update(ControlState)
                .where(ControlState.id == 1)
                .values(command=command, command_nonce=ControlState.command_nonce + 1)
            )
            session.commit()


def read_control_state(session: Session) -> dict | None:
    """Read the control row for display.

    Degrades to None if the table is absent (e.g. a DB written by an older
    monitor before _ensure_db_exists has added control_state), so the panel
    renders 'offline' instead of 500ing. Matches the dashboard's general
    missing-table tolerance."""
    try:
        row = session.get(ControlState, 1)
    except OperationalError:
        return None
    if row is None:
        return None
    return {c.name: getattr(row, c.name) for c in ControlState.__table__.columns}


def monitor_alive(state: dict | None) -> bool:
    """Heartbeat freshness check. The monitor writes last_seen_at every poll
    tick (~3s) even while idle/paused, and refreshes it periodically mid-scan
    (see runner._progress_heartbeat), so this window only ever reads 'dead' if
    the process is actually gone."""
    if not state or not state.get("last_seen_at"):
        return False
    try:
        seen = datetime.fromisoformat(state["last_seen_at"])
    except (TypeError, ValueError):
        return False
    return (
        datetime.now(timezone.utc) - seen
    ).total_seconds() < MONITOR_LIVENESS_WINDOW_S
