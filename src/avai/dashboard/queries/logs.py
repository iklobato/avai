"""The logs panel: raw entries and grouped aggregates."""

from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import (
    select,
)
from sqlalchemy.orm import Session

from avai.host_monitor import (
    LogEntryRow,
)

from .common import Page, _existing_tables

# Syslog severities, most severe first — the order the level filter offers.
LOG_LEVELS = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")


_LOG_ERROR_LEVELS = frozenset({"emerg", "alert", "crit", "err"})


@dataclass(frozen=True)
class LogFilter:
    """The logs panels' filters: a source (journald / file path), a syslog
    level, and a text search over message + unit."""

    source: str = ""
    level: str = ""
    q: str = ""

    def keep(self, rows: list[LogEntryRow]) -> list[LogEntryRow]:
        if self.source:
            rows = [r for r in rows if r.source == self.source]
        if self.level:
            rows = [r for r in rows if r.level == self.level]
        if self.q:
            needle = self.q.lower()
            rows = [
                r
                for r in rows
                if needle in (r.message or "").lower()
                or needle in (r.unit or "").lower()
            ]
        return rows

    def fields(self) -> dict:
        """The filter values a panel echoes back to its form."""
        return {"source": self.source, "level": self.level, "q": self.q}


def _run_log_lines(session: Session, run_id: str) -> list[LogEntryRow]:
    return list(
        session.execute(
            select(LogEntryRow).where(LogEntryRow.run_id == run_id)
        ).scalars()
    )


def log_entries(
    session: Session,
    run_id: str,
    filters: LogFilter = LogFilter(),
    page: Page = Page(),
) -> dict:
    """Recent host log lines (journald + tailed files) for ``run_id`` as a
    filtered, paginated, newest-first table. Returns the rows plus
    pagination + echoed-filter fields the panel expects; an empty result
    (same shape) if the table is absent (older DB) or the run captured
    nothing."""
    empty = {
        "rows": [],
        **page.fields(0),
        **filters.fields(),
        "sources": [],
        "levels": list(LOG_LEVELS),
        "summary": {"total": 0, "err": 0, "warning": 0, "sources": 0},
    }
    if "log_entries" not in _existing_tables(session):
        return empty

    rows = _run_log_lines(session, run_id)
    # Newest first: event time when known, else insertion order (id).
    rows.sort(key=lambda r: (r.event_timestamp or "", r.id), reverse=True)
    # Distinct sources for the dropdown: from the whole run, before filtering.
    sources = sorted({r.source for r in rows if r.source})
    rows = filters.keep(rows)

    summary = {
        "total": len(rows),
        "err": sum(1 for r in rows if r.level in _LOG_ERROR_LEVELS),
        "warning": sum(1 for r in rows if r.level == "warning"),
        "sources": len(sources),
    }
    page_rows, paging = page.slice(rows)
    items = [
        {
            "source": r.source,
            "unit": r.unit,
            "level": r.level,
            "event_timestamp": r.event_timestamp,
            "pid": r.pid,
            "message": r.message,
        }
        for r in page_rows
    ]
    return {
        "rows": items,
        **paging,
        **filters.fields(),
        "sources": sources,
        "levels": list(LOG_LEVELS),
        "summary": summary,
    }


_LOG_HEX_RE = re.compile(r"\b[0-9a-fA-F]{8,}\b")


_LOG_NUM_RE = re.compile(r"\d+")


_LOG_WS_RE = re.compile(r"\s+")


def _normalize_log_message(message: str | None) -> str:
    """Collapse a log line to a template so repeated events with varying ids
    aggregate together: hex tokens (hashes / uuids) and digit runs (pids,
    ports, timestamps) become ``#``. ``"Accepted password for ik from 10.0.0.5
    port 22"`` and the next login collapse to the same key."""
    if not message:
        return "(empty)"
    collapsed = _LOG_HEX_RE.sub("#", message.strip())
    collapsed = _LOG_NUM_RE.sub("#", collapsed)
    return _LOG_WS_RE.sub(" ", collapsed)[:160]


def _log_group_by_unit(row: LogEntryRow) -> str:
    return row.unit or "(none)"


def _log_group_by_source(row: LogEntryRow) -> str:
    return row.source or "(none)"


def _log_group_by_message(row: LogEntryRow) -> str:
    return _normalize_log_message(row.message)


# group_by value → key function. Doubles as the allow-list of valid dimensions.
_LOG_GROUPERS = {
    "unit": _log_group_by_unit,
    "source": _log_group_by_source,
    "message": _log_group_by_message,
}


def _log_groups(rows: list[LogEntryRow], key_of) -> list[dict]:
    """Count lines per group key, with error / warning counts, the latest
    timestamp, a sample message, and which units and sources fed it."""
    groups: dict[str, dict] = {}
    for r in rows:
        key = key_of(r)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "key": key,
                "count": 0,
                "errors": 0,
                "warnings": 0,
                "last": "",
                "sample": None,
                "_units": set(),
                "_sources": set(),
            }
        g["count"] += 1
        g["errors"] += r.level in _LOG_ERROR_LEVELS
        g["warnings"] += r.level == "warning"
        g["last"] = max(g["last"], r.event_timestamp or "")
        g["sample"] = g["sample"] or r.message or None
        g["_units"].add(r.unit)
        g["_sources"].add(r.source)
    return [_labelled_group(g) for g in groups.values()]


def _labelled_group(group: dict) -> dict:
    """Swap the unit / source sets for a label: the one name, or a count."""
    units = set(filter(None, group.pop("_units")))
    srcs = set(filter(None, group.pop("_sources")))
    group["unit_label"] = (
        next(iter(units)) if len(units) == 1 else f"{len(units)} units"
    )
    group["source_label"] = (
        next(iter(srcs)) if len(srcs) == 1 else f"{len(srcs)} sources"
    )
    return group


def log_aggregates(
    session: Session,
    run_id: str,
    filters: LogFilter = LogFilter(),
    group_by: str = "unit",
    page: Page = Page(),
) -> dict:
    """Aggregate the run's log lines into ranked groups for the log-summary
    panel. Groups by ``unit`` (systemd unit / file), ``source`` (journald vs a
    file), or ``message`` (a normalised template, so repeated events count
    together). Each group carries its occurrence count + error / warning
    counts; **ranked most-errors-first, then most-occurrences**. Takes the
    same filters as the raw view, and paginates. Empty shape if the table is
    absent."""
    group_by = group_by if group_by in _LOG_GROUPERS else "unit"
    empty = {
        "groups": [],
        **page.fields(0),
        "group_by": group_by,
        "group_options": list(_LOG_GROUPERS),
        **filters.fields(),
        "sources": [],
        "summary": {"groups": 0, "errors": 0, "warnings": 0, "lines": 0},
    }
    if "log_entries" not in _existing_tables(session):
        return empty

    rows = _run_log_lines(session, run_id)
    sources = sorted({r.source for r in rows if r.source})
    items = _log_groups(filters.keep(rows), _LOG_GROUPERS[group_by])
    # Most errors first, then most occurrences, then key for a stable order.
    items.sort(key=lambda g: (-g["errors"], -g["count"], g["key"]))

    summary = {
        "groups": len(items),
        "errors": sum(g["errors"] for g in items),
        "warnings": sum(g["warnings"] for g in items),
        "lines": sum(g["count"] for g in items),
    }
    page_rows, paging = page.slice(items)
    return {
        "groups": page_rows,
        **paging,
        "group_by": group_by,
        "group_options": list(_LOG_GROUPERS),
        **filters.fields(),
        "sources": sources,
        "summary": summary,
    }
