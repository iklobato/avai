"""Run-level queries: latest run, risk, narrative, counts, errors, alerts."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    desc,
    func,
    select,
)
from sqlalchemy.orm import Session

from avai.host_monitor import (
    CollectionRun,
    CollectorErrorRow,
    IncidentNarrativeRow,
    Judgement,
    RiskScoreRow,
    slices,
)

from .common import COLLECTOR_MODELS, VERDICTS, _existing_tables, _row_and_artifact


def latest_run(session: Session):
    """The run the dashboard should display.

    Prefer the most recent *completed* run (a consistent, fully
    populated snapshot — and no flicker to empty when the next cycle
    starts). But if nothing has completed yet — the common first-run
    case, where the monitor is still grinding through its first cycle
    (collectors + LLM judging take minutes) — fall back to the most
    recent in-progress run so the dashboard shows live, partial data
    instead of "no run yet". Otherwise the user stares at an empty
    page for the entire first cycle.
    """
    completed = session.execute(
        select(CollectionRun)
        .where(CollectionRun.finished_at.is_not(None))
        .order_by(desc(CollectionRun.started_at))
        .limit(1)
    ).scalar_one_or_none()
    if completed is not None:
        return completed
    # No completed run yet → show the latest in-progress one.
    return session.execute(
        select(CollectionRun).order_by(desc(CollectionRun.started_at)).limit(1)
    ).scalar_one_or_none()


def latest_narrative(session: Session):
    """The most recent incident digest, or None. Guarded for DBs written by
    an older monitor that predates the ``incident_narratives`` table."""
    if "incident_narratives" not in _existing_tables(session):
        return None
    return session.execute(
        select(IncidentNarrativeRow)
        .order_by(desc(IncidentNarrativeRow.created_at))
        .limit(1)
    ).scalar_one_or_none()


def latest_risk(session: Session):
    """Most recent host posture score, or None. Guarded for older DBs that
    predate the ``risk_scores`` table."""
    if "risk_scores" not in _existing_tables(session):
        return None
    return session.execute(
        select(RiskScoreRow).order_by(desc(RiskScoreRow.created_at)).limit(1)
    ).scalar_one_or_none()


def risk_trend(session: Session, limit: int = 30) -> list[int]:
    """Recent scores oldest→newest for the sparkline. [] if unavailable."""
    if "risk_scores" not in _existing_tables(session):
        return []
    rows = (
        session.execute(
            select(RiskScoreRow.score)
            .order_by(desc(RiskScoreRow.created_at))
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return list(reversed(rows))


def prior_run(session: Session, before_started: str) -> tuple[str | None, str | None]:
    """``(run_id, started_at)`` of the run immediately before
    ``before_started``, or ``(None, None)`` if it's the first run."""
    row = session.execute(
        select(CollectionRun.run_id, CollectionRun.started_at)
        .where(CollectionRun.started_at < before_started)
        .order_by(desc(CollectionRun.started_at))
        .limit(1)
    ).first()
    return (row[0], row[1]) if row else (None, None)


def recent_runs(session: Session, limit: int = 10) -> list[CollectionRun]:
    return list(
        session.execute(
            select(CollectionRun).order_by(desc(CollectionRun.started_at)).limit(limit)
        ).scalars()
    )


def runs_total(session: Session) -> int:
    return (
        session.execute(select(func.count()).select_from(CollectionRun)).scalar() or 0
    )


def verdict_counts(session: Session) -> dict[str, int]:
    return dict(
        session.execute(
            select(Judgement.verdict, func.count(Judgement.content_hash)).group_by(
                Judgement.verdict
            )
        ).all()
    )


def judged_since(session: Session, since: str) -> int:
    return (
        session.execute(
            select(func.count(Judgement.content_hash)).where(
                Judgement.created_at >= since
            )
        ).scalar()
        or 0
    )


def cost_since(session: Session, since: str) -> float:
    """Total estimated LLM cost (USD) of judgments produced since ``since``."""
    return float(
        session.execute(
            select(func.coalesce(func.sum(Judgement.cost_usd), 0.0)).where(
                Judgement.created_at >= since
            )
        ).scalar()
        or 0.0
    )


_STREAMING_COLLECTORS = {s.name for s in slices.ALL if s.streaming}


def row_counts(
    session: Session,
    latest_run_id: str,
    latest_started: str,
    prev_run_id: str | None = None,
    prev_started: str | None = None,
) -> list[dict]:
    """Per-collector row counts for the latest run, with a change signal vs
    the previous run.

    Snapshot collectors are counted by ``run_id`` (already indexed) instead
    of a ``collected_at`` range — turning per-table full scans into index
    counts. Streaming collectors use an ``event_timestamp`` window (also
    indexed). ``delta``/``is_new`` describe the change vs the previous run.
    """
    out = []
    present = _existing_tables(session)
    for name, model in COLLECTOR_MODELS.items():
        if model.__tablename__ not in present:
            continue
        if name in _STREAMING_COLLECTORS:
            # streaming tables accumulate across sessions → time window
            ts = model.event_timestamp
            cur = session.execute(
                select(func.count()).select_from(model).where(ts >= latest_started)
            ).scalar()
            prev = (
                session.execute(
                    select(func.count())
                    .select_from(model)
                    .where(ts >= prev_started, ts < latest_started)
                ).scalar()
                if prev_started is not None
                else None
            )
        else:
            # snapshot tables are keyed by run_id (indexed)
            cur = session.execute(
                select(func.count())
                .select_from(model)
                .where(model.run_id == latest_run_id)
            ).scalar()
            prev = (
                session.execute(
                    select(func.count())
                    .select_from(model)
                    .where(model.run_id == prev_run_id)
                ).scalar()
                if prev_run_id is not None
                else None
            )
        cur = cur or 0
        delta = (cur - (prev or 0)) if prev is not None else None
        is_new = prev == 0 and cur > 0 if prev is not None else False
        out.append({"name": name, "rows": cur, "delta": delta, "is_new": is_new})
    out.sort(key=lambda x: x["rows"], reverse=True)
    return out


def collector_errors(session: Session, run_id: str) -> list[CollectorErrorRow]:
    return list(
        session.execute(
            select(CollectorErrorRow).where(CollectorErrorRow.run_id == run_id)
        ).scalars()
    )


def new_alerts(session: Session, since: str | None, limit: int = 50) -> list[dict]:
    """Return malicious / suspicious judgements created after ``since``,
    newest first. Drives the browser-side toast + beep alert. Each
    item carries enough context to render a self-contained card
    (verdict, collector, category, reasoning, remediation, artifact)
    without requiring a follow-up request.

    Note: this returns *judgements*, not snapshot rows. A judgement is
    created exactly once per unique content_hash. So the same artifact
    won't alert twice across runs (the dedupe is intrinsic).
    """
    stmt = select(Judgement).where(Judgement.verdict.in_(("malicious", "suspicious")))
    if since:
        stmt = stmt.where(Judgement.created_at > since)
    stmt = stmt.order_by(desc(Judgement.created_at)).limit(limit)

    items = []
    for j in session.execute(stmt).scalars():
        _, artifact = _row_and_artifact(session, j)
        items.append(
            {
                "content_hash": j.content_hash,
                "collector": j.collector,
                "verdict": j.verdict,
                "category": j.category or "none",
                "confidence": j.confidence or 0.0,
                "reasoning": j.reasoning or "",
                "remediation": j.remediation or "",
                "created_at": j.created_at,
                "artifact": artifact,
            }
        )
    return items


def verdict_timeseries(session: Session, hours: int = 12) -> dict:
    """Return verdict counts grouped per-hour bucket over the last N hours.
    Returns: {"labels": [...iso hours...], "datasets": {verdict: [counts...]}}
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(
        timespec="seconds"
    )
    # 'YYYY-MM-DDTHH' is the first 13 chars of an ISO timestamp.
    rows = session.execute(
        select(
            func.substr(Judgement.created_at, 1, 13).label("hour"),
            Judgement.verdict,
            func.count().label("n"),
        )
        .where(Judgement.created_at >= cutoff)
        .group_by("hour", Judgement.verdict)
        .order_by("hour")
    ).all()
    buckets: dict[str, dict[str, int]] = {}
    for hour, verdict, n in rows:
        buckets.setdefault(hour, {})
        buckets[hour][verdict] = buckets[hour].get(verdict, 0) + n
    labels = sorted(buckets.keys())
    datasets = {v: [buckets[h].get(v, 0) for h in labels] for v in VERDICTS}
    return {"labels": labels, "datasets": datasets}
