"""Live activity for the panels board: events per minute and the newest
process starts. Both read the streaming tables, which the monitor flushes
every few seconds, so they move while a cycle is still running."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from avai.host_monitor import AuthEventRow, ProcessExecRow

from .panel_reads import SchemaProbe

# 'YYYY-MM-DDTHH:MM' (or with a space) is the first 16 chars of a stamp.
MINUTE_PREFIX_CHARS = 16
# Characters 12-16 of that prefix are the 'HH:MM' label.
CLOCK_START = 11
PERCENT = 100
# 'HH:MM:SS' ends three characters after the minute prefix.
SECOND_END_CHARS = MINUTE_PREFIX_CHARS + len(":SS")
# A bar that has events never draws thinner than this, so it stays visible.
MIN_BAR_PERCENT = 2


@dataclass(frozen=True)
class MinuteStamp:
    """A minute prefix in the table's own format. The exec stream stores UTC
    with a 'T'; the auth stream stores host time with a space. Each window
    stays inside one table, so string order is time order."""

    text: str

    def minus(self, minutes: int) -> MinuteStamp:
        separator = self.text[len("YYYY-MM-DD")]
        pattern = f"%Y-%m-%d{separator}%H:%M"
        moved = datetime.strptime(self.text, pattern) - timedelta(minutes=minutes)
        return MinuteStamp(moved.strftime(pattern))

    def clock(self) -> str:
        return self.text[CLOCK_START:MINUTE_PREFIX_CHARS]


class StreamRate:
    """Events per minute over the last ``minutes`` minutes of one streaming
    table, ending at its newest event (not at 'now', so a stopped monitor
    still shows its last real activity, with its real times)."""

    def __init__(self, session: Session, model: type[Any]) -> None:
        self._session = session
        self._model = model

    def per_minute(self, minutes: int) -> dict[str, Any]:
        empty = {"bars": [], "peak": 0, "first": "", "last": "", "total": 0}
        if self._model.__tablename__ not in SchemaProbe(self._session).tables():
            return empty
        newest = self._session.execute(
            select(func.max(self._model.event_timestamp))
        ).scalar()
        if not newest:
            return empty
        last = MinuteStamp(newest[:MINUTE_PREFIX_CHARS])
        return self._bars(last.minus(minutes - 1), last)

    def _bars(self, first: MinuteStamp, last: MinuteStamp) -> dict[str, Any]:
        minute = func.substr(self._model.event_timestamp, 1, MINUTE_PREFIX_CHARS)
        statement = (
            select(minute.label("minute"), func.count().label("events"))
            .where(self._model.event_timestamp >= first.text)
            .group_by("minute")
            .order_by("minute")
        )
        counts = [
            (MinuteStamp(prefix), events)
            for prefix, events in self._session.execute(statement)
        ]
        peak = max((events for _, events in counts), default=0)
        return {
            "bars": [BarHeight(peak).of(stamp, events) for stamp, events in counts],
            "peak": peak,
            "first": first.text,
            "last": last.text,
            "total": sum(events for _, events in counts),
        }


@dataclass(frozen=True)
class BarHeight:
    peak: int

    def of(self, stamp: MinuteStamp, count: int) -> dict[str, Any]:
        share = count / self.peak * PERCENT if self.peak else 0
        return {
            "clock": stamp.clock(),
            "count": count,
            "height": max(MIN_BAR_PERCENT, round(share)),
        }


class ExecFeed:
    """The newest process starts, newest first."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def latest(self, limit: int) -> list[dict[str, Any]]:
        if ProcessExecRow.__tablename__ not in SchemaProbe(self._session).tables():
            return []
        statement = (
            select(ProcessExecRow)
            .order_by(
                desc(ProcessExecRow.event_timestamp), desc(ProcessExecRow.id)
            )
            .limit(limit)
        )
        rows = self._session.execute(statement).scalars()
        return [self._item(row) for row in rows]

    def _item(self, row: ProcessExecRow) -> dict[str, Any]:
        return {
            "time": (row.event_timestamp or "")[CLOCK_START:SECOND_END_CHARS],
            "exe_path": row.exe_path or "",
            "pid": row.pid,
            "signing_id": row.signing_id or "",
            "unsigned": not row.signing_id,
        }


class ActivityStreams:
    """The two streams the Activity row charts."""

    def exec_rate(self, session: Session, minutes: int) -> dict[str, Any]:
        return StreamRate(session, ProcessExecRow).per_minute(minutes)

    def auth_rate(self, session: Session, minutes: int) -> dict[str, Any]:
        return StreamRate(session, AuthEventRow).per_minute(minutes)
