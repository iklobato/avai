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

from .common import DEFAULT_PER_PAGE, _cache_key, _existing_tables

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


def auth_events_aggregated(
    session: Session,
    q: str = "",
    subsystem: str = "",
    verdict: str = "",
    sort: str = "count",
    page: int = 1,
    per_page: int = DEFAULT_PER_PAGE,
):
    """Auth events grouped by content_hash (one pattern per unique log line),
    joined with LLM verdicts.  Collapses raw log lines into patterns; each
    pattern gets one judgment from the LLM judge.  Supports filtering by
    subsystem, verdict, and free-text search, and sorting by count or verdict
    severity.  Results are cached for ``_AUTH_AGG_TTL`` seconds (see above)."""
    cache_key = (_cache_key(session), q, subsystem, verdict, sort, page, per_page)
    cached = _auth_agg_cache.get(cache_key)
    if cached is not None and time.monotonic() - cached[0] < _AUTH_AGG_TTL:
        return cached[1]

    empty = {
        "rows": [],
        "summary": {},
        "subsystem_tabs": _auth_subsystem_tabs({}, 0),
        "total": 0,
        "total_events": 0,
        "page": 1,
        "per_page": per_page,
        "total_pages": 1,
        "q": q,
        "subsystem": subsystem,
        "verdict": verdict,
        "sort": sort,
    }
    if AuthEventRow.__tablename__ not in _existing_tables(session):
        return empty

    # Bound the aggregation to a recent window on the indexed event_timestamp.
    # auth_events accumulates indefinitely (100k+ rows); without this the
    # GROUP BY scans the whole table on every poll.
    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=_AUTH_AGG_WINDOW_HOURS)
    ).isoformat(timespec="seconds")

    # --- summary counts per subsystem (recent window) ---
    # Filter-independent (same for every tab), so cache it per-DB and share it
    # across all subsystem tabs instead of recomputing the ~300k-row GROUP BY
    # on each cold tab load.
    summary, total_events = _auth_summary(session, cutoff)

    # --- aggregation: one row per unique (content_hash) pattern ---
    conds = [AuthEventRow.event_timestamp >= cutoff]
    if q:
        like = f"%{q}%"
        conds.append(
            or_(
                AuthEventRow.process.ilike(like),
                AuthEventRow.event_message.ilike(like),
            )
        )
    if subsystem:
        conds.append(AuthEventRow.subsystem == subsystem)

    # Group by content_hash alone — it is 1:1 with (process, subsystem,
    # event_message), so this yields identical patterns while grouping on the
    # indexed column instead of sorting the long event_message text. The other
    # display columns are functionally dependent, so min() returns their (sole)
    # value.
    agg_sub = (
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

    # Join with Judgement so each pattern carries its LLM verdict.
    outer = select(
        agg_sub.c.content_hash,
        agg_sub.c.process,
        agg_sub.c.subsystem,
        agg_sub.c.event_message,
        agg_sub.c.cnt,
        agg_sub.c.last_seen,
        Judgement.verdict,
        Judgement.confidence,
        Judgement.reasoning,
    ).outerjoin(
        Judgement,
        and_(
            Judgement.content_hash == agg_sub.c.content_hash,
            Judgement.collector == "auth_events",
        ),
    )

    if verdict:
        if verdict == "unjudged":
            outer = outer.where(Judgement.verdict.is_(None))
        else:
            outer = outer.where(Judgement.verdict == verdict)

    total = (
        session.execute(select(func.count()).select_from(outer.subquery())).scalar()
        or 0
    )

    per_page = max(1, min(per_page, 200))
    page = max(1, page)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)

    if sort == "verdict":
        sev_case = case(
            _AUTH_VERDICT_SEV,
            value=Judgement.verdict,
            else_=99,
        )
        order_by = (sev_case.asc(), agg_sub.c.cnt.desc())
    else:
        order_by = (agg_sub.c.cnt.desc(),)

    page_stmt = outer.order_by(*order_by).offset((page - 1) * per_page).limit(per_page)

    rows = []
    for ch, proc, sub, msg, cnt, last, verd, conf, reason in session.execute(
        page_stmt
    ).all():
        rows.append(
            {
                "process": Path(proc).name if proc else "—",
                "subsystem": sub or "",
                "subsystem_short": _AUTH_SUBSYSTEM_LABELS.get(
                    sub, (sub or "").split(".")[-1] or "—"
                ),
                "message": msg or "",
                "count": cnt,
                "last_seen": (last or "")[:16].replace("T", " "),
                "verdict": verd,
                "confidence": conf,
                "reasoning": reason,
            }
        )

    result = {
        "rows": rows,
        "summary": summary,
        "total_events": total_events,
        "subsystem_tabs": _auth_subsystem_tabs(summary, total_events),
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "q": q,
        "subsystem": subsystem,
        "verdict": verdict,
        "sort": sort,
    }

    with _auth_agg_cache_lock:
        if len(_auth_agg_cache) >= _AUTH_AGG_CACHE_MAX:
            _auth_agg_cache.clear()
        _auth_agg_cache[cache_key] = (time.monotonic(), result)
    return result
