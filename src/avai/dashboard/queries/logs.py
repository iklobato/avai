"""The logs panel: raw entries and grouped aggregates."""

from __future__ import annotations

import re

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


def log_entries(
    session: Session,
    run_id: str,
    *,
    source: str = "",
    level: str = "",
    q: str = "",
    page: Page = Page(),
) -> dict:
    """Recent host log lines (journald + tailed files) for ``run_id`` as a
    filtered, paginated, newest-first table. Supports a ``source`` filter
    (journald / file path), a ``level`` filter (syslog severity), and a text
    search ``q`` over message + unit. Returns the rows plus pagination +
    echoed-filter fields the panel expects; an empty result (same shape) if
    the table is absent (older DB) or the run captured nothing."""
    empty = {
        "rows": [],
        **page.fields(0),
        "source": source,
        "level": level,
        "q": q,
        "sources": [],
        "levels": list(LOG_LEVELS),
        "summary": {"total": 0, "err": 0, "warning": 0, "sources": 0},
    }
    if "log_entries" not in _existing_tables(session):
        return empty

    rows = list(
        session.execute(
            select(LogEntryRow).where(LogEntryRow.run_id == run_id)
        ).scalars()
    )
    # Newest first: event time when known, else insertion order (id).
    rows.sort(key=lambda r: (r.event_timestamp or "", r.id), reverse=True)
    # Distinct sources for the dropdown — from the whole run, before filtering.
    sources = sorted({r.source for r in rows if r.source})

    if source:
        rows = [r for r in rows if r.source == source]
    if level:
        rows = [r for r in rows if r.level == level]
    if q:
        ql = q.lower()
        rows = [
            r
            for r in rows
            if ql in (r.message or "").lower() or ql in (r.unit or "").lower()
        ]

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
        "source": source,
        "level": level,
        "q": q,
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


def log_aggregates(
    session: Session,
    run_id: str,
    *,
    group_by: str = "unit",
    source: str = "",
    q: str = "",
    page: Page = Page(),
) -> dict:
    """Aggregate the run's log lines into ranked groups for the log-summary
    panel. Groups by ``unit`` (systemd unit / file), ``source`` (journald vs a
    file), or ``message`` (a normalised template, so repeated events count
    together). Each group carries its occurrence count + error / warning
    counts; **ranked most-errors-first, then most-occurrences**. Supports the
    same ``source`` / ``q`` filters as the raw view, and paginates. Empty shape
    if the table is absent."""
    group_by = group_by if group_by in _LOG_GROUPERS else "unit"
    empty = {
        "groups": [],
        **page.fields(0),
        "group_by": group_by,
        "group_options": list(_LOG_GROUPERS),
        "source": source,
        "q": q,
        "sources": [],
        "summary": {"groups": 0, "errors": 0, "warnings": 0, "lines": 0},
    }
    if "log_entries" not in _existing_tables(session):
        return empty

    rows = list(
        session.execute(
            select(LogEntryRow).where(LogEntryRow.run_id == run_id)
        ).scalars()
    )
    sources = sorted({r.source for r in rows if r.source})
    if source:
        rows = [r for r in rows if r.source == source]
    if q:
        ql = q.lower()
        rows = [
            r
            for r in rows
            if ql in (r.message or "").lower() or ql in (r.unit or "").lower()
        ]

    key_of = _LOG_GROUPERS[group_by]
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
        if r.level in _LOG_ERROR_LEVELS:
            g["errors"] += 1
        elif r.level == "warning":
            g["warnings"] += 1
        ts = r.event_timestamp or ""
        if ts > g["last"]:
            g["last"] = ts
        if g["sample"] is None and r.message:
            g["sample"] = r.message
        if r.unit:
            g["_units"].add(r.unit)
        if r.source:
            g["_sources"].add(r.source)

    items = list(groups.values())
    # Most errors first, then most occurrences, then key for a stable order.
    items.sort(key=lambda g: (-g["errors"], -g["count"], g["key"]))
    for g in items:
        units = g.pop("_units")
        srcs = g.pop("_sources")
        g["unit_label"] = (
            next(iter(units)) if len(units) == 1 else f"{len(units)} units"
        )
        g["source_label"] = (
            next(iter(srcs)) if len(srcs) == 1 else f"{len(srcs)} sources"
        )

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
        "source": source,
        "q": q,
        "sources": sources,
        "summary": summary,
    }
