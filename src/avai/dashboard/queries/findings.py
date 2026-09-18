"""The findings panel: judged rows, their filters and sort orders."""

from __future__ import annotations

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
    _HIDDEN_SOURCE_FIELDS,
    COLLECTOR_MODELS,
    DISPLAY_FIELDS,
    VERDICTS,
    Page,
    _parse_json_obj,
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


def findings(
    session: Session,
    *,
    verdict: str = "",
    collector: str = "",
    category: str = "",
    search: str = "",
    status: str = "active",
    sort: str = "severity",
    order: str = "desc",
    page: Page = Page(),
) -> dict:
    """Paginated, filterable, sortable findings query.

    ``status`` is one of ``active`` / ``resolved`` / ``all``. A
    judgment is *active* if its ``last_seen_at`` matches the latest
    snapshot run's ``started_at``; otherwise (including NULL) it is
    *resolved* — the underlying artifact has gone away.

    Returns ``{items, total, page, per_page, total_pages,
                latest_started_at}``.
    """
    latest = latest_run(session)
    latest_started = latest.started_at if latest else None

    stmt = select(Judgement)

    if verdict and verdict in VERDICTS:
        stmt = stmt.where(Judgement.verdict == verdict)
    else:
        stmt = stmt.where(Judgement.verdict != "benign")
    if collector:
        stmt = stmt.where(Judgement.collector == collector)
    if category:
        stmt = stmt.where(Judgement.category == category)
    if search:
        like = f"%{search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Judgement.reasoning).like(like),
                func.lower(Judgement.remediation).like(like),
                func.lower(Judgement.collector).like(like),
                func.lower(Judgement.category).like(like),
            )
        )

    if latest_started and status == "active":
        stmt = stmt.where(Judgement.last_seen_at >= latest_started)
    elif latest_started and status == "resolved":
        stmt = stmt.where(
            or_(
                Judgement.last_seen_at < latest_started,
                Judgement.last_seen_at.is_(None),
            )
        )
    # status == "all" or no latest_run yet → no extra filter

    total = (
        session.execute(select(func.count()).select_from(stmt.subquery())).scalar() or 0
    )

    sort_col = _SORT_FIELDS.get(sort, _SEVERITY_CASE)
    if sort == "severity":
        # severity ascending + confidence descending is the natural pairing
        stmt = stmt.order_by(
            _SEVERITY_CASE.asc(),
            Judgement.confidence.desc(),
            Judgement.created_at.desc(),
        )
    else:
        direction = asc if order == "asc" else desc
        stmt = stmt.order_by(direction(sort_col), Judgement.created_at.desc())

    page = page.within(total)
    stmt = stmt.offset(page.offset).limit(page.size)

    raw = session.execute(stmt).scalars().all()

    # Batch the artifact lookup: one query per collector (content_hash IN …)
    # instead of one per finding. Keep the latest row per content_hash.
    hashes_by_collector: dict[str, set[str]] = {}
    for j in raw:
        hashes_by_collector.setdefault(j.collector, set()).add(j.content_hash)
    artifacts: dict[tuple, tuple] = {}
    for collector, hashes in hashes_by_collector.items():
        model = COLLECTOR_MODELS.get(collector)
        if model is None:
            continue
        seen: set[str] = set()
        for row_obj in session.execute(
            select(model)
            .where(model.content_hash.in_(hashes))
            .order_by(model.collected_at.desc())
        ).scalars():
            if row_obj.content_hash in seen:  # desc order → first is latest
                continue
            seen.add(row_obj.content_hash)
            full = {
                col.name: getattr(row_obj, col.name)
                for col in model.__table__.columns
                if col.name not in _HIDDEN_SOURCE_FIELDS
            }
            fields = DISPLAY_FIELDS.get(collector, ())
            artifacts[(collector, row_obj.content_hash)] = (
                full,
                " · ".join(
                    str(full[f]) for f in fields if full.get(f) not in (None, "")
                ),
            )

    items = []
    for j in raw:
        source_row, artifact = artifacts.get((j.collector, j.content_hash), ({}, ""))
        is_active = bool(
            latest_started and j.last_seen_at and j.last_seen_at >= latest_started
        )
        items.append(
            {
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
        )

    return {
        "items": items,
        **page.fields(total),
        "latest_started_at": latest_started,
    }
