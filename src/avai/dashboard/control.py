"""Writable control-plane access for the dashboard.

Kept separate from the read-only ``queries`` layer, which only ever gets a
strictly read-only engine (``mode=ro``); control needs a writable one. The
dashboard's ONLY writes are to the single ``control_state`` row and to
operator feedback: the monitor stays the sole writer of telemetry. WAL + a
``busy_timeout`` keep the two processes from colliding on that one row
(writes are tiny and rare).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from avai.host_monitor import ControlState, FeedbackRow
from avai.host_monitor.constants import MONITOR_LIVENESS_WINDOW_S
from avai.host_monitor.enums import FeedbackLabel, MaintenanceCommand

# The control_state table holds one row with this id.
CONTROL_ROW_ID = 1


@dataclass(frozen=True)
class SettingsChange:
    """The settings form; a None field leaves that setting as it is."""

    interval: int | None = None
    judge: bool | None = None
    enrich: bool | None = None

    def values(self) -> dict[str, int]:
        candidates = (
            ("interval_override", self.interval),
            ("judge_enabled", self.judge),
            ("enrich_enabled", self.enrich),
        )
        return {column: int(value) for column, value in candidates if value is not None}


@dataclass(frozen=True)
class Feedback:
    """An operator correction on one finding."""

    content_hash: str
    collector: str
    label: FeedbackLabel
    note: str | None
    artifact: str | None

    def fields(self, created_at: str) -> dict[str, Any]:
        """The columns a re-submitted correction overwrites."""
        return {
            "label": self.label.value,
            "note": self.note,
            "artifact": self.artifact,
            "created_at": created_at,
            "applied": 0,
        }


class ControlStore:
    """The dashboard's writes, through one writable engine per app."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def pause(self) -> None:
        self._update({"paused": 1})

    def resume(self) -> None:
        self._update({"paused": 0})

    def bump_scan_now(self) -> None:
        """Request an immediate scan (the monitor runs one cycle within a poll
        tick)."""
        self._update({"scan_now_nonce": ControlState.scan_now_nonce + 1})

    def set_settings(self, change: SettingsChange) -> None:
        values = change.values()
        if values:
            self._update(values)

    def enable_collector(self, name: str) -> None:
        self._edit_disabled(name, set.discard)

    def disable_collector(self, name: str) -> None:
        self._edit_disabled(name, set.add)

    def queue_command(self, command: MaintenanceCommand) -> None:
        """Queue a one-shot maintenance command; the monitor runs + acks it."""
        self._update(
            {"command": command.value, "command_nonce": ControlState.command_nonce + 1}
        )

    def record_feedback(self, feedback: Feedback) -> None:
        """Persist an operator correction (latest wins per finding). The
        monitor applies it to the verdict and feeds it back to the judge next
        cycle; it stays the sole writer of findings."""
        fields = feedback.fields(
            datetime.now(timezone.utc).isoformat(timespec="seconds")
        )
        keys = {"content_hash": feedback.content_hash, "collector": feedback.collector}
        statement = (
            sqlite_insert(FeedbackRow)
            .values(**keys, **fields)
            .on_conflict_do_update(index_elements=list(keys), set_=fields)
        )
        with Session(self._engine) as session:
            session.execute(statement)
            session.commit()

    def _edit_disabled(
        self, name: str, change: Callable[[set[str], str], None]
    ) -> None:
        with Session(self._engine) as session:
            self._ensure_row(session)
            row = session.get(ControlState, CONTROL_ROW_ID)
            raw = (row.disabled_collectors or "").split(",")
            current = {entry.strip() for entry in raw if entry.strip()}
            change(current, name)
            row.disabled_collectors = ",".join(sorted(current)) or None
            session.commit()

    def _update(self, values: dict[str, Any]) -> None:
        statement = (
            update(ControlState).where(ControlState.id == CONTROL_ROW_ID).values(values)
        )
        with Session(self._engine) as session:
            self._ensure_row(session)
            session.execute(statement)
            session.commit()

    def _ensure_row(self, session: Session) -> None:
        # The model's column defaults populate the NOT NULL counters.
        statement = sqlite_insert(ControlState).values(id=CONTROL_ROW_ID)
        session.execute(statement.on_conflict_do_nothing())


class ControlReader:
    """The control row for display. None when the table is absent (a DB
    written by an older monitor), so the panel renders 'offline' instead of
    500ing."""

    def read(self, session: Session) -> dict[str, Any] | None:
        try:
            row = session.get(ControlState, CONTROL_ROW_ID)
        except OperationalError:
            return None
        if row is None:
            return None
        columns = ControlState.__table__.columns
        return {column.name: getattr(row, column.name) for column in columns}


class MonitorLiveness:
    """Heartbeat freshness. The monitor writes last_seen_at every poll tick
    (~3s) even while idle or paused, and refreshes it mid-scan, so this only
    reads 'dead' when the process is actually gone."""

    def alive(self, state: dict[str, Any] | None) -> bool:
        if not state or not state.get("last_seen_at"):
            return False
        try:
            seen = datetime.fromisoformat(state["last_seen_at"])
        except (TypeError, ValueError):
            return False
        age = (datetime.now(timezone.utc) - seen).total_seconds()
        return age < MONITOR_LIVENESS_WINDOW_S
