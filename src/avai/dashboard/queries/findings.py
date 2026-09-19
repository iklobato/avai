"""The findings panel: judged rows, their filters and sort orders."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import (
    asc,
    case,
    desc,
    func,
    or_,
    select,
)
from sqlalchemy.orm import Session

from avai.host_monitor import (
    Judgement,
)

from .collection import latest_run
from .common import (
    COLLECTOR_MODELS,
    VERDICTS,
    Page,
    _artifact_label,
    _parse_json_obj,
    _source_row,
)

_SEVERITY_CASE = case(
    {"malicious": 0, "suspicious": 1, "unknown": 2, "benign": 3},
    value=Judgement.verdict,
    else_=99,
)


_SORT_FIELDS = {
    "severity": _SEVERITY_CASE,
    "verdict": Judgement.verdict,
    "collector": Judgement.collector,
    "category": Judgement.category,
    "confidence": Judgement.confidence,
    "judged": Judgement.created_at,
}


def collector_options(session: Session) -> list[str]:
    rows = session.execute(
        select(Judgement.collector).distinct().order_by(Judgement.collector)
    ).all()
    return [r[0] for r in rows if r[0]]


def category_options(session: Session) -> list[str]:
    rows = session.execute(
        select(Judgement.category)
        .where(Judgement.category.is_not(None))
        .distinct()
        .order_by(Judgement.category)
    ).all()
    return [r[0] for r in rows if r[0]]


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
    status: str = "active"

    def apply(self, stmt, latest_started):
        """``stmt`` narrowed to these filters. Benign is hidden unless picked."""
        if self.verdict in VERDICTS:
            stmt = stmt.where(Judgement.verdict == self.verdict)
        else:
            stmt = stmt.where(Judgement.verdict != "benign")
        if self.collector:
            stmt = stmt.where(Judgement.collector == self.collector)
        if self.category:
            stmt = stmt.where(Judgement.category == self.category)
        if self.search:
            like = f"%{self.search.lower()}%"
            stmt = stmt.where(
                or_(
                    func.lower(Judgement.reasoning).like(like),
                    func.lower(Judgement.remediation).like(like),
                    func.lower(Judgement.collector).like(like),
                    func.lower(Judgement.category).like(like),
                )
            )
        return self._apply_status(stmt, latest_started)

    def _apply_status(self, stmt, latest_started):
        # With no latest run yet, or status "all", there is nothing to narrow.
        if not latest_started:
            return stmt
        if self.status == "active":
            return stmt.where(Judgement.last_seen_at >= latest_started)
        if self.status == "resolved":
            return stmt.where(
                or_(
                    Judgement.last_seen_at < latest_started,
                    Judgement.last_seen_at.is_(None),
                )
            )
        return stmt


def _ordered(stmt, sort: str, order: str):
    if sort == "severity":
        # severity ascending + confidence descending is the natural pairing
        return stmt.order_by(
            _SEVERITY_CASE.asc(),
            Judgement.confidence.desc(),
            Judgement.created_at.desc(),
        )
    direction = asc if order == "asc" else desc
    sort_col = _SORT_FIELDS.get(sort, _SEVERITY_CASE)
    return stmt.order_by(direction(sort_col), Judgement.created_at.desc())


def _latest_source_rows(session: Session, judgements) -> dict[tuple, tuple]:
    """``(collector, content_hash) -> (source_row, artifact_label)`` for the
    latest observation of each judged artifact. Batched: one query per
    collector (content_hash IN ...) instead of one per finding."""
    hashes_by_collector: dict[str, set[str]] = {}
    for j in judgements:
        hashes_by_collector.setdefault(j.collector, set()).add(j.content_hash)
    artifacts: dict[tuple, tuple] = {}
    for collector, hashes in hashes_by_collector.items():
        model = COLLECTOR_MODELS.get(collector)
        if model is None:
            continue
        for row_obj in session.execute(
            select(model)
            .where(model.content_hash.in_(hashes))
            .order_by(model.collected_at.desc())
        ).scalars():
            # Newest first, so the first row seen per hash is the latest.
            key = (collector, row_obj.content_hash)
            if key not in artifacts:
                full = _source_row(row_obj)
                artifacts[key] = (full, _artifact_label(collector, full))
    return artifacts


def _finding_item(j: Judgement, artifacts: dict, latest_started) -> dict:
    source_row, artifact = artifacts.get((j.collector, j.content_hash), ({}, ""))
    is_active = bool(
        latest_started and j.last_seen_at and j.last_seen_at >= latest_started
    )
    return {
        "verdict": j.verdict,
        "collector": j.collector,
        "category": j.category or "none",
        "confidence": j.confidence or 0.0,
        "reasoning": j.reasoning or "",
        "remediation": j.remediation or "",
        "created_at": j.created_at,
        "last_seen_at": j.last_seen_at,
        "status": "active" if is_active else "resolved",
        "artifact": artifact,
        "source_row": source_row,
        "content_hash": j.content_hash,
        "novel": bool(getattr(j, "novel", 0)),
        "context": _parse_json_obj(getattr(j, "context_json", None)),
        "cost_usd": getattr(j, "cost_usd", None) or 0.0,
    }


def findings(
    session: Session,
    *,
    filters: FindingFilter = FindingFilter(),
    sort: str = "severity",
    order: str = "desc",
    page: Page = Page(),
) -> dict:
    """Paginated, filterable, sortable findings query.

    Returns ``{items, total, page, per_page, total_pages,
                latest_started_at}``.
    """
    latest = latest_run(session)
    latest_started = latest.started_at if latest else None

    stmt = filters.apply(select(Judgement), latest_started)
    total = (
        session.execute(select(func.count()).select_from(stmt.subquery())).scalar() or 0
    )
    page = page.within(total)
    stmt = _ordered(stmt, sort, order).offset(page.offset).limit(page.size)
    raw = session.execute(stmt).scalars().all()

    artifacts = _latest_source_rows(session, raw)
    return {
        "items": [_finding_item(j, artifacts, latest_started) for j in raw],
        **page.fields(total),
        "latest_started_at": latest_started,
    }
