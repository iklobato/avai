"""The authentication events panel, aggregated per subsystem."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, ClassVar

from sqlalchemy import Select, and_, case, func, or_, select
from sqlalchemy.orm import Session

from avai.host_monitor import AuthEventRow, Judgement
from avai.host_monitor.enums import Verdict
from avai.host_monitor.runtime import Clock

from .panel_reads import Page, RowFilter, SchemaProbe

# (subsystem, the short label the tabs and rows show)
SUBSYSTEM_LABELS = (
    ("com.apple.securityd", "securityd"),
    ("com.apple.TCC", "TCC"),
    ("com.apple.opendirectoryd", "opendirectoryd"),
    ("com.apple.syspolicy", "syspolicy"),
    ("com.apple.loginwindow.logging", "loginwindow"),
    ("com.apple.launchservices", "launchservices"),
    ("com.apple.Authorization", "Authorization"),
    ("com.apple.xpc", "xpc"),
    ("com.apple.CFPasteboard", "CFPasteboard"),
    ("com.apple.BezelServices", "BezelServices"),
    ("com.apple.ManagedClient", "ManagedClient"),
)

AUTH_SUBSYSTEM_OPTIONS = (
    ("all subsystems", ""),
    ("TCC (privacy access)", "com.apple.TCC"),
    ("securityd", "com.apple.securityd"),
    ("syspolicy (Gatekeeper)", "com.apple.syspolicy"),
    ("opendirectoryd", "com.apple.opendirectoryd"),
    ("loginwindow", "com.apple.loginwindow.logging"),
    ("Authorization", "com.apple.Authorization"),
    ("launchservices", "com.apple.launchservices"),
)


class SubsystemNames:
    def short(self, subsystem: str | None, fallback: str) -> str:
        """The tab label for a subsystem: its known short name, else the
        last dotted segment, else ``fallback``."""
        known = dict(SUBSYSTEM_LABELS).get(subsystem or "")
        return known or (subsystem or "").split(".")[-1] or fallback

    def tabs(self, summary: dict[str, int], total_events: int) -> list[dict[str, Any]]:
        """Tab descriptors for the subsystem tablist: short label, filter
        value and event count (the "all" tab carries the grand total)."""
        tabs = []
        for _label, value in AUTH_SUBSYSTEM_OPTIONS:
            if not value:
                tabs.append({"label": "all", "val": "", "count": total_events})
                continue
            short = self.short(value, value)
            tabs.append({"label": short, "val": value, "count": summary.get(short, 0)})
        return tabs


@dataclass(frozen=True)
class AuthQuery:
    filters: RowFilter = field(default_factory=RowFilter)
    subsystem: str = ""
    sort: str = "count"
    page: Page = field(default_factory=Page)

    def echoed(self) -> dict[str, Any]:
        return {**self.filters.fields(), "subsystem": self.subsystem, "sort": self.sort}


class AuthEventsPanel:
    """Auth events grouped by content_hash (one pattern per unique log line),
    joined with LLM verdicts. Filters by subsystem, verdict (``unjudged`` for
    none yet) and free text; sorts by count or verdict severity.

    Aggregating ~300k raw rows into ~80k patterns costs seconds and reruns on
    every tab click and the panel's 30s poll, so results are cached briefly
    (below the poll cadence, so never staler than the dashboard already is)."""

    WINDOW_HOURS = 24
    TTL_S = 15.0
    CACHE_MAX = 64
    SUMMARY_SUBSYSTEMS = 12
    MINUTE_CHARS = 16  # "YYYY-MM-DDTHH:MM"
    _pages: ClassVar[dict[tuple[Any, ...], tuple[float, dict[str, Any]]]] = {}
    _pages_lock: ClassVar[threading.Lock] = threading.Lock()
    _summaries: ClassVar[dict[str, tuple[float, tuple[dict[str, int], int]]]] = {}
    _summaries_lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(self, session: Session, clock: Clock) -> None:
        self._session = session
        self._clock = clock

    def aggregated(self, query: AuthQuery) -> dict[str, Any]:
        key = (str(self._session.get_bind().url), query)
        cached = self._pages.get(key)
        if cached is not None and time.monotonic() - cached[0] < self.TTL_S:
            return cached[1]
        if AuthEventRow.__tablename__ not in SchemaProbe(self._session).tables():
            return self._empty(query)
        panel_page = self._page(query)
        with self._pages_lock:
            if len(self._pages) >= self.CACHE_MAX:
                self._pages.clear()
            self._pages[key] = (time.monotonic(), panel_page)
        return panel_page

    def _empty(self, query: AuthQuery) -> dict[str, Any]:
        return {
            "rows": [],
            "summary": {},
            "subsystem_tabs": SubsystemNames().tabs({}, 0),
            **query.page.fields(0),
            "total_events": 0,
            **query.echoed(),
        }

    def _page(self, query: AuthQuery) -> dict[str, Any]:
        # A recent window on the indexed event_timestamp: auth_events grows
        # without bound and the GROUP BY would otherwise scan the whole table.
        since = self._clock.now() - timedelta(hours=self.WINDOW_HOURS)
        cutoff = since.isoformat(timespec="seconds")
        summary, total_events = self._summary(cutoff)
        patterns, count_column = self._patterns(query, cutoff)
        total = self._total(patterns)
        page = query.page.within(total)
        ordered = patterns.order_by(*self._order(query.sort, count_column))
        found = self._session.execute(ordered.offset(page.offset).limit(page.size))
        return {
            "rows": [self._row(pattern) for pattern in found.all()],
            "summary": summary,
            "total_events": total_events,
            "subsystem_tabs": SubsystemNames().tabs(summary, total_events),
            **page.fields(total),
            **query.echoed(),
        }

    def _total(self, patterns: Select[Any]) -> int:
        counted = select(func.count()).select_from(patterns.subquery())
        return self._session.execute(counted).scalar() or 0

    def _summary(self, cutoff: str) -> tuple[dict[str, int], int]:
        """Recent per-subsystem event counts plus the grand total. The same
        for every tab, so cached per DB and shared across them."""
        key = str(self._session.get_bind().url)
        hit = self._summaries.get(key)
        if hit is not None and time.monotonic() - hit[0] < self.TTL_S:
            return hit[1]
        rows = self._subsystem_counts(cutoff)
        names = SubsystemNames()
        summary = {
            names.short(subsystem or "(none)", ""): count for subsystem, count in rows
        }
        value = (summary, sum(summary.values()))
        with self._summaries_lock:
            self._summaries[key] = (time.monotonic(), value)
        return value

    def _subsystem_counts(self, cutoff: str) -> list[Any]:
        statement = (
            select(AuthEventRow.subsystem, func.count().label("cnt"))
            .where(AuthEventRow.event_timestamp >= cutoff)
            .group_by(AuthEventRow.subsystem)
            .order_by(func.count().desc())
            .limit(self.SUMMARY_SUBSYSTEMS)
        )
        return list(self._session.execute(statement).all())

    def _patterns(self, query: AuthQuery, cutoff: str) -> tuple[Select[Any], Any]:
        """One row per unique log line in the window with its count, last
        sighting and LLM verdict; plus the count column to order by."""
        aggregate = self._aggregate(query, cutoff)
        judged = and_(
            Judgement.content_hash == aggregate.c.content_hash,
            Judgement.collector == "auth_events",
        )
        patterns = select(
            aggregate.c.process,
            aggregate.c.subsystem,
            aggregate.c.event_message,
            aggregate.c.cnt,
            aggregate.c.last_seen,
            Judgement.verdict,
            Judgement.confidence,
            Judgement.reasoning,
        ).outerjoin(Judgement, judged)
        return self._verdict_filter(patterns, query.filters.verdict), aggregate.c.cnt

    def _aggregate(self, query: AuthQuery, cutoff: str) -> Any:
        # Group by content_hash alone: it is 1:1 with (process, subsystem,
        # event_message), so the patterns are identical while grouping on the
        # indexed column; min() returns the dependent columns' sole value.
        return (
            select(
                AuthEventRow.content_hash,
                func.min(AuthEventRow.process).label("process"),
                func.min(AuthEventRow.subsystem).label("subsystem"),
                func.min(AuthEventRow.event_message).label("event_message"),
                func.count().label("cnt"),
                func.max(AuthEventRow.event_timestamp).label("last_seen"),
            )
            .where(*self._conditions(query, cutoff))
            .group_by(AuthEventRow.content_hash)
            .subquery("agg")
        )

    def _conditions(self, query: AuthQuery, cutoff: str) -> list[Any]:
        conditions: list[Any] = [AuthEventRow.event_timestamp >= cutoff]
        if query.filters.search:
            like = f"%{query.filters.search}%"
            conditions.append(
                or_(
                    AuthEventRow.process.ilike(like),
                    AuthEventRow.event_message.ilike(like),
                )
            )
        if query.subsystem:
            conditions.append(AuthEventRow.subsystem == query.subsystem)
        return conditions

    def _verdict_filter(self, patterns: Select[Any], verdict: str) -> Select[Any]:
        if verdict == "unjudged":
            return patterns.where(Judgement.verdict.is_(None))
        if verdict:
            return patterns.where(Judgement.verdict == verdict)
        return patterns

    def _order(self, sort: str, count_column: Any) -> tuple[Any, ...]:
        if sort != "verdict":
            return (count_column.desc(),)
        ranks = Verdict.ranks()
        severity = case(ranks, value=Judgement.verdict, else_=len(ranks))
        return (severity.asc(), count_column.desc())

    def _row(self, pattern: Any) -> dict[str, Any]:
        subsystem = pattern.subsystem
        return {
            "process": Path(pattern.process).name if pattern.process else "—",
            "subsystem": subsystem or "",
            "subsystem_short": SubsystemNames().short(subsystem, "—"),
            "message": pattern.event_message or "",
            "count": pattern.cnt,
            "last_seen": (pattern.last_seen or "")[: self.MINUTE_CHARS].replace(
                "T", " "
            ),
            "verdict": pattern.verdict,
            "confidence": pattern.confidence,
            "reasoning": pattern.reasoning,
        }
