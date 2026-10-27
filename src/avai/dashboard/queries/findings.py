"""The findings panel: judged rows, their filters and sort orders."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sqlalchemy import Select, asc, case, desc, func, or_, select
from sqlalchemy.orm import Session

from avai.host_monitor import Judgement
from avai.host_monitor.enums import Verdict

from .collection import RunQueries
from .panel_reads import CollectorTables, FindingSource, Page, StoredJson


class FindingOptions:
    """The values the findings filter dropdowns offer."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def collectors(self) -> list[str]:
        statement = select(Judgement.collector).distinct().order_by(Judgement.collector)
        return [row[0] for row in self._session.execute(statement).all() if row[0]]

    def categories(self) -> list[str]:
        statement = (
            select(Judgement.category)
            .where(Judgement.category.is_not(None))
            .distinct()
            .order_by(Judgement.category)
        )
        return [row[0] for row in self._session.execute(statement).all() if row[0]]


class FindingStatus(StrEnum):
    """Whether a judgment's artifact is still present in the latest run."""

    ACTIVE = "active"
    RESOLVED = "resolved"
    ALL = "all"

    @classmethod
    def parse(cls, text: str) -> FindingStatus:
        """The status a request asked for; anything unknown shows all, which
        is what an unknown value already did."""
        return cls(text) if text in tuple(cls) else cls.ALL


@dataclass(frozen=True)
class FindingFilter:
    """What the findings panel narrows to. ``status`` is ``active`` /
    ``resolved`` / ``all``: a judgment is *active* if its ``last_seen_at``
    reaches the latest snapshot run's ``started_at``; otherwise (including
    NULL) it is *resolved*, meaning the underlying artifact has gone away."""

    verdict: str = ""
    collector: str = ""
    category: str = ""
    search: str = ""
    status: FindingStatus = FindingStatus.ACTIVE

    def apply(self, statement: Select[Any], latest_started: str | None) -> Select[Any]:
        """``statement`` narrowed to these filters. Benign is hidden unless
        picked."""
        if self.verdict in Verdict.worst_first():
            statement = statement.where(Judgement.verdict == self.verdict)
        else:
            statement = statement.where(Judgement.verdict != Verdict.BENIGN)
        if self.collector:
            statement = statement.where(Judgement.collector == self.collector)
        if self.category:
            statement = statement.where(Judgement.category == self.category)
        return self._status(self._searched(statement), latest_started)

    def _searched(self, statement: Select[Any]) -> Select[Any]:
        if not self.search:
            return statement
        like = f"%{self.search.lower()}%"
        fields = (
            Judgement.reasoning,
            Judgement.remediation,
            Judgement.collector,
            Judgement.category,
        )
        return statement.where(
            or_(*(func.lower(column).like(like) for column in fields))
        )

    def _status(
        self, statement: Select[Any], latest_started: str | None
    ) -> Select[Any]:
        # With no latest run yet, or status "all", there is nothing to narrow.
        if not latest_started:
            return statement
        conditions = {
            FindingStatus.ACTIVE: Judgement.last_seen_at >= latest_started,
            FindingStatus.RESOLVED: or_(
                Judgement.last_seen_at < latest_started,
                Judgement.last_seen_at.is_(None),
            ),
        }
        condition = conditions.get(self.status)
        return statement if condition is None else statement.where(condition)


class FindingSort:
    """The orders the findings table can be sorted by."""

    def ordered(self, statement: Select[Any], sort: str, order: str) -> Select[Any]:
        severity = self._severity()
        if sort == "severity":
            # severity ascending + confidence descending is the natural pairing
            return statement.order_by(
                severity.asc(), Judgement.confidence.desc(), Judgement.created_at.desc()
            )
        direction = asc if order == "asc" else desc
        column = self._columns(severity).get(sort, severity)
        return statement.order_by(direction(column), Judgement.created_at.desc())

    def _severity(self) -> Any:
        ranks = Verdict.ranks()
        return case(ranks, value=Judgement.verdict, else_=len(ranks))

    def _columns(self, severity: Any) -> dict[str, Any]:
        return {
            "severity": severity,
            "verdict": Judgement.verdict,
            "collector": Judgement.collector,
            "category": Judgement.category,
            "confidence": Judgement.confidence,
            "judged": Judgement.created_at,
        }


@dataclass(frozen=True)
class FindingsQuery:
    filters: FindingFilter = field(default_factory=FindingFilter)
    sort: str = "severity"
    order: str = "desc"
    page: Page = field(default_factory=Page)


class FindingsPanel:
    """Paginated, filterable, sortable findings."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def findings(self, query: FindingsQuery) -> dict[str, Any]:
        """``{items, total, page, per_page, total_pages, latest_started_at}``."""
        latest = RunQueries(self._session).latest_run()
        latest_started = latest.started_at if latest else None
        statement = query.filters.apply(select(Judgement), latest_started)
        counted = select(func.count()).select_from(statement.subquery())
        total = self._session.execute(counted).scalar() or 0
        page = query.page.within(total)
        statement = FindingSort().ordered(statement, query.sort, query.order)
        found = self._session.execute(statement.offset(page.offset).limit(page.size))
        judgments = found.scalars().all()
        artifacts = self._latest_source_rows(judgments)
        return {
            "items": [
                self._item(judgment, artifacts, latest_started)
                for judgment in judgments
            ],
            **page.fields(total),
            "latest_started_at": latest_started,
        }

    def _latest_source_rows(
        self, judgments: Sequence[Judgement]
    ) -> dict[tuple[str, str], tuple[dict[str, Any], str]]:
        """``(collector, content_hash) -> (source_row, artifact_label)`` for the
        latest observation of each judged artifact. One query per collector
        (content_hash IN ...) instead of one per finding."""
        hashes: dict[str, set[str]] = {}
        for judgment in judgments:
            hashes.setdefault(judgment.collector, set()).add(judgment.content_hash)
        artifacts: dict[tuple[str, str], tuple[dict[str, Any], str]] = {}
        for collector, wanted in hashes.items():
            artifacts.update(self._newest(collector, wanted))
        return artifacts

    def _newest(
        self, collector: str, wanted: set[str]
    ) -> dict[tuple[str, str], tuple[dict[str, Any], str]]:
        model = CollectorTables().model(collector)
        if model is None:
            return {}
        statement = (
            select(model)
            .where(model.content_hash.in_(wanted))
            .order_by(model.collected_at.desc())
        )
        source = FindingSource(self._session)
        newest: dict[tuple[str, str], tuple[dict[str, Any], str]] = {}
        # Newest first, so the first row seen per hash is the latest.
        for row_obj in self._session.execute(statement).scalars():
            key = (collector, row_obj.content_hash)
            if key not in newest:
                full = source.source_row(row_obj)
                newest[key] = (full, source.artifact_label(collector, full))
        return newest

    def _item(
        self,
        judgment: Judgement,
        artifacts: dict[tuple[str, str], tuple[dict[str, Any], str]],
        latest_started: str | None,
    ) -> dict[str, Any]:
        source = artifacts.get((judgment.collector, judgment.content_hash), ({}, ""))
        seen = judgment.last_seen_at
        is_active = bool(latest_started and seen and seen >= latest_started)
        status = FindingStatus.ACTIVE if is_active else FindingStatus.RESOLVED
        return FindingItem(judgment, status).values(source)


class FindingItem:
    """One finding as the findings table renders it."""

    def __init__(self, judgment: Judgement, status: FindingStatus) -> None:
        self._judgment = judgment
        self._status = status

    def values(self, source: tuple[dict[str, Any], str]) -> dict[str, Any]:
        judgment = self._judgment
        source_row, artifact = source
        return {
            "verdict": judgment.verdict,
            "collector": judgment.collector,
            "category": judgment.category or "none",
            "confidence": judgment.confidence or 0.0,
            "reasoning": judgment.reasoning or "",
            "remediation": judgment.remediation or "",
            "created_at": judgment.created_at,
            "last_seen_at": judgment.last_seen_at,
            "status": self._status.value,
            "artifact": artifact,
            "source_row": source_row,
            "content_hash": judgment.content_hash,
            "novel": bool(judgment.novel or 0),
            "context": StoredJson().as_dict(judgment.context_json),
            "cost_usd": judgment.cost_usd or 0.0,
        }
