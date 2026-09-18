"""The authentication events panel, aggregated per subsystem."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import (
    and_,
    case,
    func,
    or_,
    select,
)
from sqlalchemy.orm import Session

from avai.host_monitor import (
    AuthEventRow,
    Judgement,
)

from .common import Page, RowFilter, _cache_key, _existing_tables

_AUTH_SUBSYSTEM_LABELS = {
    "com.apple.securityd": "securityd",
    "com.apple.TCC": "TCC",
    "com.apple.opendirectoryd": "opendirectoryd",
    "com.apple.syspolicy": "syspolicy",
    "com.apple.loginwindow.logging": "loginwindow",
    "com.apple.launchservices": "launchservices",
    "com.apple.Authorization": "Authorization",
    "com.apple.xpc": "xpc",
    "com.apple.CFPasteboard": "CFPasteboard",
    "com.apple.BezelServices": "BezelServices",
    "com.apple.ManagedClient": "ManagedClient",
}


AUTH_SUBSYSTEM_OPTIONS = [
    ("all subsystems", ""),
    ("TCC (privacy access)", "com.apple.TCC"),
    ("securityd", "com.apple.securityd"),
    ("syspolicy (Gatekeeper)", "com.apple.syspolicy"),
    ("opendirectoryd", "com.apple.opendirectoryd"),
    ("loginwindow", "com.apple.loginwindow.logging"),
    ("Authorization", "com.apple.Authorization"),
    ("launchservices", "com.apple.launchservices"),
]


def _auth_subsystem_tabs(summary: dict, total_events: int) -> list[dict]:
    """Tab descriptors for the auth-events subsystem tablist: short label,
    filter value, and event count (the "all" tab carries the grand total).
    Counts come from the per-subsystem ``summary`` keyed by short label."""
    tabs = []
    for _label, val in AUTH_SUBSYSTEM_OPTIONS:
        if not val:
            tabs.append({"label": "all", "val": "", "count": total_events})
            continue
        short = _AUTH_SUBSYSTEM_LABELS.get(val, val.split(".")[-1])
        tabs.append({"label": short, "val": val, "count": summary.get(short, 0)})
    return tabs


_AUTH_VERDICT_SEV = {"malicious": 0, "suspicious": 1, "unknown": 2, "benign": 3}


_AUTH_AGG_WINDOW_HOURS = 24


# Aggregating ~300k raw rows into ~80k patterns (GROUP BY + COUNT + page)
# costs several seconds and is rerun on every subsystem-tab click and on the
# panel's 30s poll. Cache the full result briefly so tab switching is instant;
# the TTL is below the panel's poll cadence, so this never shows staler data
# than the dashboard already does. Mirrors the _tables_cache pattern above.
_AUTH_AGG_TTL = 15.0


_auth_agg_cache: dict[tuple, tuple[float, dict]] = {}


_auth_agg_cache_lock = threading.Lock()


_AUTH_AGG_CACHE_MAX = 64


# Per-subsystem summary is identical for every tab, so cache it per-DB
# (filter-independent) and reuse it across all subsystem tabs.
_auth_summary_cache: dict[str, tuple[float, tuple[dict, int]]] = {}


_auth_summary_cache_lock = threading.Lock()


def _auth_summary(session: Session, cutoff: str) -> tuple[dict, int]:
    """Recent per-subsystem event counts (short label -> count) plus the grand
    total, cached for ``_AUTH_AGG_TTL`` seconds and shared across all tabs."""
    key = _cache_key(session)
    hit = _auth_summary_cache.get(key)
    if hit is not None and time.monotonic() - hit[0] < _AUTH_AGG_TTL:
        return hit[1]
    summary_rows = session.execute(
        select(AuthEventRow.subsystem, func.count().label("cnt"))
        .where(AuthEventRow.event_timestamp >= cutoff)
        .group_by(AuthEventRow.subsystem)
        .order_by(func.count().desc())
        .limit(12)
    ).all()
    summary = {
        _AUTH_SUBSYSTEM_LABELS.get(s, (s or "(none)").split(".")[-1]): c
        for s, c in summary_rows
    }
    value = (summary, sum(summary.values()))
    with _auth_summary_cache_lock:
        _auth_summary_cache[key] = (time.monotonic(), value)
    return value


def _auth_patterns(filters: RowFilter, subsystem: str, cutoff: str):
    """One row per unique log line (content_hash) in the window, with its
    count, last sighting and LLM verdict. Returns the select and the count
    column to order by."""
    conds = [AuthEventRow.event_timestamp >= cutoff]
    if filters.q:
        like = f"%{filters.q}%"
        conds.append(
            or_(
                AuthEventRow.process.ilike(like),
                AuthEventRow.event_message.ilike(like),
            )
        )
    if subsystem:
        conds.append(AuthEventRow.subsystem == subsystem)

    # Group by content_hash alone: it is 1:1 with (process, subsystem,
    # event_message), so this yields identical patterns while grouping on the
    # indexed column instead of sorting the long event_message text. The other
    # display columns are functionally dependent, so min() returns their (sole)
    # value.
    agg = (
        select(
            AuthEventRow.content_hash,
            func.min(AuthEventRow.process).label("process"),
            func.min(AuthEventRow.subsystem).label("subsystem"),
            func.min(AuthEventRow.event_message).label("event_message"),
            func.count().label("cnt"),
            func.max(AuthEventRow.event_timestamp).label("last_seen"),
        )
        .where(*conds)
        .group_by(AuthEventRow.content_hash)
        .subquery("agg")
    )
    patterns = select(
        agg.c.process,
        agg.c.subsystem,
        agg.c.event_message,
        agg.c.cnt,
        agg.c.last_seen,
        Judgement.verdict,
        Judgement.confidence,
        Judgement.reasoning,
    ).outerjoin(
        Judgement,
        and_(
            Judgement.content_hash == agg.c.content_hash,
            Judgement.collector == "auth_events",
        ),
    )
    if filters.verdict == "unjudged":
        patterns = patterns.where(Judgement.verdict.is_(None))
    elif filters.verdict:
        patterns = patterns.where(Judgement.verdict == filters.verdict)
    return patterns, agg.c.cnt


def _auth_order(sort: str, count_col) -> tuple:
    if sort != "verdict":
        return (count_col.desc(),)
    severity = case(_AUTH_VERDICT_SEV, value=Judgement.verdict, else_=99)
    return (severity.asc(), count_col.desc())


def _auth_row(pattern) -> dict:
    sub = pattern.subsystem
    return {
        "process": Path(pattern.process).name if pattern.process else "—",
        "subsystem": sub or "",
        "subsystem_short": _AUTH_SUBSYSTEM_LABELS.get(
            sub, (sub or "").split(".")[-1] or "—"
        ),
        "message": pattern.event_message or "",
        "count": pattern.cnt,
        "last_seen": (pattern.last_seen or "")[:16].replace("T", " "),
        "verdict": pattern.verdict,
        "confidence": pattern.confidence,
        "reasoning": pattern.reasoning,
    }


def _remember_auth_page(cache_key: tuple, result: dict) -> None:
    with _auth_agg_cache_lock:
        if len(_auth_agg_cache) >= _AUTH_AGG_CACHE_MAX:
            _auth_agg_cache.clear()
        _auth_agg_cache[cache_key] = (time.monotonic(), result)


def auth_events_aggregated(
    session: Session,
    filters: RowFilter = RowFilter(),
    subsystem: str = "",
    sort: str = "count",
    page: Page = Page(),
):
    """Auth events grouped by content_hash (one pattern per unique log line),
    joined with LLM verdicts.  Collapses raw log lines into patterns; each
    pattern gets one judgment from the LLM judge.  Supports filtering by
    subsystem, verdict (``unjudged`` for none yet), and free-text search, and
    sorting by count or verdict severity.  Results are cached for
    ``_AUTH_AGG_TTL`` seconds (see above)."""
    cache_key = (_cache_key(session), filters, subsystem, sort, page)
    cached = _auth_agg_cache.get(cache_key)
    if cached is not None and time.monotonic() - cached[0] < _AUTH_AGG_TTL:
        return cached[1]

    echoed = {**filters.fields(), "subsystem": subsystem, "sort": sort}
    if AuthEventRow.__tablename__ not in _existing_tables(session):
        return {
            "rows": [],
            "summary": {},
            "subsystem_tabs": _auth_subsystem_tabs({}, 0),
            **page.fields(0),
            "total_events": 0,
            **echoed,
        }

    # Bound the aggregation to a recent window on the indexed event_timestamp.
    # auth_events accumulates indefinitely (100k+ rows); without this the
    # GROUP BY scans the whole table on every poll.
    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=_AUTH_AGG_WINDOW_HOURS)
    ).isoformat(timespec="seconds")
    # Filter-independent (same for every tab), so it is cached per-DB and
    # shared across all subsystem tabs.
    summary, total_events = _auth_summary(session, cutoff)

    patterns, count_col = _auth_patterns(filters, subsystem, cutoff)
    total = (
        session.execute(select(func.count()).select_from(patterns.subquery())).scalar()
        or 0
    )
    page = page.within(total)
    page_stmt = (
        patterns.order_by(*_auth_order(sort, count_col))
        .offset(page.offset)
        .limit(page.size)
    )
    result = {
        "rows": [_auth_row(p) for p in session.execute(page_stmt).all()],
        "summary": summary,
        "total_events": total_events,
        "subsystem_tabs": _auth_subsystem_tabs(summary, total_events),
        **page.fields(total),
        **echoed,
    }
    _remember_auth_page(cache_key, result)
    return result
