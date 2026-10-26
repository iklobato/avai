"""The logs panel: raw entries and grouped aggregates."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from avai.host_monitor import LogEntryRow

from .panel_reads import Page, SchemaProbe

# Syslog severities, most severe first: the order the level filter offers.
LOG_LEVELS = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")

ERROR_LEVELS = frozenset({"emerg", "alert", "crit", "err"})

GROUP_DIMENSIONS = ("unit", "source", "message")


@dataclass(frozen=True)
class LogFilter:
    """The logs panels' filters: a source (journald / file path), a syslog
    level, and a text search over message + unit."""

    source: str = ""
    level: str = ""
    search: str = ""

    def keep(self, rows: list[LogEntryRow]) -> list[LogEntryRow]:
        kept = [
            row
            for row in rows
            if (not self.source or row.source == self.source)
            and (not self.level or row.level == self.level)
        ]
        if not self.search:
            return kept
        needle = self.search.lower()
        return [
            row
            for row in kept
            if needle in (row.message or "").lower()
            or needle in (row.unit or "").lower()
        ]

    def fields(self) -> dict[str, str]:
        """The filter values a panel echoes back to its form."""
        return {"source": self.source, "level": self.level, "q": self.search}


class LogTemplate:
    """Collapse a log line to a template so repeated events with varying ids
    aggregate together: hex tokens (hashes / uuids) and digit runs (pids,
    ports, timestamps) become ``#``. ``"Accepted password for ik from
    10.0.0.5 port 22"`` and the next login collapse to the same key."""

    HEX = re.compile(r"\b[0-9a-fA-F]{8,}\b")
    DIGITS = re.compile(r"\d+")
    SPACES = re.compile(r"\s+")
    MAX_CHARS = 160

    def of(self, message: str | None) -> str:
        if not message:
            return "(empty)"
        collapsed = self.DIGITS.sub("#", self.HEX.sub("#", message.strip()))
        return self.SPACES.sub(" ", collapsed)[: self.MAX_CHARS]


class LogGroupKey:
    """The key a log line groups under for each grouping dimension."""

    def for_dimension(self, dimension: str) -> Callable[[LogEntryRow], str]:
        keys = {"unit": self._unit, "source": self._source, "message": self._message}
        return keys[dimension]

    def _unit(self, row: LogEntryRow) -> str:
        return row.unit or "(none)"

    def _source(self, row: LogEntryRow) -> str:
        return row.source or "(none)"

    def _message(self, row: LogEntryRow) -> str:
        return LogTemplate().of(row.message)


class LogGroup:
    """Lines sharing one group key: their count, error / warning counts, the
    latest timestamp, a sample message, and which units and sources fed it."""

    def __init__(self, key: str) -> None:
        self._key = key
        self._rows: list[LogEntryRow] = []

    def add(self, row: LogEntryRow) -> None:
        self._rows.append(row)

    def values(self) -> dict[str, Any]:
        rows = self._rows
        samples = [row.message for row in rows if row.message]
        return {
            "key": self._key,
            "count": len(rows),
            "errors": sum(1 for row in rows if row.level in ERROR_LEVELS),
            "warnings": sum(1 for row in rows if row.level == "warning"),
            "last": max(row.event_timestamp or "" for row in rows),
            "sample": samples[0] if samples else None,
            "unit_label": self._label({row.unit for row in rows}, "units"),
            "source_label": self._label({row.source for row in rows}, "sources"),
        }

    def _label(self, names: set[str | None], plural: str) -> str:
        """The one name, or a count when several fed the group."""
        named = set(filter(None, names))
        return next(iter(named)) if len(named) == 1 else f"{len(named)} {plural}"


@dataclass(frozen=True)
class LogQuery:
    filters: LogFilter = field(default_factory=LogFilter)
    page: Page = field(default_factory=Page)


@dataclass(frozen=True)
class LogAggregateQuery:
    filters: LogFilter = field(default_factory=LogFilter)
    group_by: str = "unit"
    page: Page = field(default_factory=Page)

    def dimension(self) -> str:
        return self.group_by if self.group_by in GROUP_DIMENSIONS else "unit"


class LogsPanel:
    """Recent host log lines (journald + tailed files) for a run. Both views
    return the same empty shape when the table is absent (older DB) or the
    run captured nothing."""

    def __init__(self, session: Session, run_id: str) -> None:
        self._session = session
        self._run_id = run_id

    def entries(self, query: LogQuery) -> dict[str, Any]:
        """A filtered, paginated, newest-first table."""
        rows = sorted(self._lines(), key=self._newest, reverse=True)
        # Distinct sources for the dropdown: from the whole run, before filtering.
        sources = sorted({row.source for row in rows if row.source})
        kept = query.filters.keep(rows)
        page_rows, paging = query.page.slice(kept)
        return {
            "rows": [self._entry(row) for row in page_rows],
            **paging,
            **query.filters.fields(),
            "sources": sources,
            "levels": list(LOG_LEVELS),
            "summary": self._entry_summary(kept, sources),
        }

    def aggregates(self, query: LogAggregateQuery) -> dict[str, Any]:
        """Ranked groups by ``unit`` (systemd unit / file), ``source``
        (journald vs a file) or ``message`` (a normalised template); **most
        errors first, then most occurrences**. Same filters as the raw view,
        paginated."""
        rows = self._lines()
        sources = sorted({row.source for row in rows if row.source})
        groups = self._groups(query.filters.keep(rows), query.dimension())
        page_rows, paging = query.page.slice(sorted(groups, key=self._rank))
        return {
            "groups": page_rows,
            **paging,
            "group_by": query.dimension(),
            "group_options": list(GROUP_DIMENSIONS),
            **query.filters.fields(),
            "sources": sources,
            "summary": self._group_summary(groups),
        }

    def _entry_summary(
        self, kept: list[LogEntryRow], sources: list[str]
    ) -> dict[str, int]:
        return {
            "total": len(kept),
            "err": sum(1 for row in kept if row.level in ERROR_LEVELS),
            "warning": sum(1 for row in kept if row.level == "warning"),
            "sources": len(sources),
        }

    def _lines(self) -> list[LogEntryRow]:
        if "log_entries" not in SchemaProbe(self._session).tables():
            return []
        statement = select(LogEntryRow).where(LogEntryRow.run_id == self._run_id)
        return list(self._session.execute(statement).scalars())

    def _newest(self, row: LogEntryRow) -> tuple[str, int]:
        # Event time when known, else insertion order (id).
        return row.event_timestamp or "", row.id

    def _entry(self, row: LogEntryRow) -> dict[str, Any]:
        return {
            "source": row.source,
            "unit": row.unit,
            "level": row.level,
            "event_timestamp": row.event_timestamp,
            "pid": row.pid,
            "message": row.message,
        }

    def _groups(self, rows: list[LogEntryRow], dimension: str) -> list[dict[str, Any]]:
        key_of = LogGroupKey().for_dimension(dimension)
        groups: dict[str, LogGroup] = {}
        for row in rows:
            key = key_of(row)
            groups.setdefault(key, LogGroup(key)).add(row)
        return [group.values() for group in groups.values()]

    def _rank(self, group: dict[str, Any]) -> tuple[int, int, str]:
        # Most errors first, then most occurrences, then key for a stable order.
        return -group["errors"], -group["count"], group["key"]

    def _group_summary(self, groups: list[dict[str, Any]]) -> dict[str, int]:
        return {
            "groups": len(groups),
            "errors": sum(group["errors"] for group in groups),
            "warnings": sum(group["warnings"] for group in groups),
            "lines": sum(group["count"] for group in groups),
        }
