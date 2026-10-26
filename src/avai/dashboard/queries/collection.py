"""Run-level queries: latest run, risk, narrative, counts, errors, alerts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from avai.host_monitor import (
    CollectionRun,
    CollectorErrorRow,
    IncidentNarrativeRow,
    Judgement,
    RiskScoreRow,
)
from avai.host_monitor.models import _RowBase
from avai.host_monitor.slices import Slices

from .panel_reads import VERDICTS, CollectorTables, FindingSource, SchemaProbe


class RunQueries:
    """Collection runs: which one to show, its neighbours and its errors."""

    RECENT_RUNS = 10

    def __init__(self, session: Session) -> None:
        self._session = session

    def latest_run(self) -> CollectionRun | None:
        """The run the dashboard should display.

        Prefer the most recent *completed* run (a consistent, fully populated
        snapshot, and no flicker to empty when the next cycle starts). If
        nothing has completed yet (the first cycle, which takes minutes),
        fall back to the most recent in-progress run so the dashboard shows
        live, partial data instead of "no run yet"."""
        newest = select(CollectionRun).order_by(desc(CollectionRun.started_at)).limit(1)
        completed = self._session.execute(
            newest.where(CollectionRun.finished_at.is_not(None))
        ).scalar_one_or_none()
        if completed is not None:
            return completed
        return self._session.execute(newest).scalar_one_or_none()

    def prior_run(self, before_started: str) -> tuple[str | None, str | None]:
        """``(run_id, started_at)`` of the run immediately before
        ``before_started``, or ``(None, None)`` if it's the first run."""
        row = self._session.execute(
            select(CollectionRun.run_id, CollectionRun.started_at)
            .where(CollectionRun.started_at < before_started)
            .order_by(desc(CollectionRun.started_at))
            .limit(1)
        ).first()
        return (row[0], row[1]) if row else (None, None)

    def recent_runs(self, limit: int = RECENT_RUNS) -> list[CollectionRun]:
        statement = (
            select(CollectionRun).order_by(desc(CollectionRun.started_at)).limit(limit)
        )
        return list(self._session.execute(statement).scalars())

    def runs_total(self) -> int:
        statement = select(func.count()).select_from(CollectionRun)
        return self._session.execute(statement).scalar() or 0

    def collector_errors(self, run_id: str) -> list[CollectorErrorRow]:
        statement = select(CollectorErrorRow).where(CollectorErrorRow.run_id == run_id)
        return list(self._session.execute(statement).scalars())


class ReportQueries:
    """The latest incident digest and posture score. Guarded for DBs written
    by an older monitor that predates their tables."""

    TREND_POINTS = 30

    def __init__(self, session: Session) -> None:
        self._session = session

    def latest_narrative(self) -> IncidentNarrativeRow | None:
        if "incident_narratives" not in SchemaProbe(self._session).tables():
            return None
        statement = (
            select(IncidentNarrativeRow)
            .order_by(desc(IncidentNarrativeRow.created_at))
            .limit(1)
        )
        return self._session.execute(statement).scalar_one_or_none()

    def latest_risk(self) -> RiskScoreRow | None:
        if "risk_scores" not in SchemaProbe(self._session).tables():
            return None
        statement = (
            select(RiskScoreRow).order_by(desc(RiskScoreRow.created_at)).limit(1)
        )
        return self._session.execute(statement).scalar_one_or_none()

    def risk_trend(self, limit: int = TREND_POINTS) -> list[int]:
        """Recent scores oldest to newest for the sparkline. [] if unavailable."""
        if "risk_scores" not in SchemaProbe(self._session).tables():
            return []
        statement = (
            select(RiskScoreRow.score)
            .order_by(desc(RiskScoreRow.created_at))
            .limit(limit)
        )
        return list(reversed(self._session.execute(statement).scalars().all()))


class VerdictQueries:
    """Counts, costs and alerts over the judge's verdicts."""

    ALERT_LIMIT = 50
    TIMESERIES_HOURS = 12
    # 'YYYY-MM-DDTHH' is the first 13 chars of an ISO timestamp.
    HOUR_PREFIX_CHARS = 13

    def __init__(self, session: Session) -> None:
        self._session = session

    def verdict_counts(self) -> dict[str, int]:
        statement = select(
            Judgement.verdict, func.count(Judgement.content_hash)
        ).group_by(Judgement.verdict)
        return dict(self._session.execute(statement).all())

    def judged_since(self, since: str) -> int:
        statement = select(func.count(Judgement.content_hash)).where(
            Judgement.created_at >= since
        )
        return self._session.execute(statement).scalar() or 0

    def cost_since(self, since: str) -> float:
        """Total estimated LLM cost (USD) of judgments produced since ``since``."""
        total = func.coalesce(func.sum(Judgement.cost_usd), 0.0)
        statement = select(total).where(Judgement.created_at >= since)
        return float(self._session.execute(statement).scalar() or 0.0)

    def new_alerts(
        self, since: str | None, limit: int = ALERT_LIMIT
    ) -> list[dict[str, Any]]:
        """Malicious / suspicious judgements created after ``since``, newest
        first, each with enough context to render a self-contained toast.
        A judgement exists once per content_hash, so an artifact never
        alerts twice across runs."""
        statement = select(Judgement).where(
            Judgement.verdict.in_(("malicious", "suspicious"))
        )
        if since:
            statement = statement.where(Judgement.created_at > since)
        statement = statement.order_by(desc(Judgement.created_at)).limit(limit)
        return [
            self._alert(judgment)
            for judgment in self._session.execute(statement).scalars()
        ]

    def _alert(self, judgment: Judgement) -> dict[str, Any]:
        _, artifact = FindingSource(self._session).row_and_artifact(judgment)
        return {
            "content_hash": judgment.content_hash,
            "collector": judgment.collector,
            "verdict": judgment.verdict,
            "category": judgment.category or "none",
            "confidence": judgment.confidence or 0.0,
            "reasoning": judgment.reasoning or "",
            "remediation": judgment.remediation or "",
            "created_at": judgment.created_at,
            "artifact": artifact,
        }

    def verdict_timeseries(self, hours: int = TIMESERIES_HOURS) -> dict[str, Any]:
        """Verdict counts per hour over the last ``hours`` hours:
        ``{"labels": [...iso hours...], "datasets": {verdict: [counts...]}}``."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(
            timespec="seconds"
        )
        buckets = self._hourly(cutoff)
        labels = sorted(buckets)
        datasets = {
            verdict: [buckets[label].get(verdict, 0) for label in labels]
            for verdict in VERDICTS
        }
        return {"labels": labels, "datasets": datasets}

    def _hourly(self, cutoff: str) -> dict[str, dict[str, int]]:
        hour = func.substr(Judgement.created_at, 1, self.HOUR_PREFIX_CHARS).label(
            "hour"
        )
        statement = (
            select(hour, Judgement.verdict, func.count().label("n"))
            .where(Judgement.created_at >= cutoff)
            .group_by("hour", Judgement.verdict)
            .order_by("hour")
        )
        buckets: dict[str, dict[str, int]] = {}
        for bucket, verdict, count in self._session.execute(statement).all():
            counts = buckets.setdefault(bucket, {})
            counts[verdict] = counts.get(verdict, 0) + count
        return buckets


@dataclass(frozen=True)
class RunMark:
    """A run as row counts see it: its id and when it started."""

    run_id: str | None
    started: str | None


@dataclass(frozen=True)
class RunPair:
    latest: RunMark
    previous: RunMark


class RunCounter(Protocol):
    def latest(self, runs: RunPair) -> int: ...

    def previous(self, runs: RunPair) -> int | None: ...


class SnapshotCount:
    """Rows a snapshot collector wrote in a run, counted by ``run_id``."""

    def __init__(self, session: Session, model: type[_RowBase]) -> None:
        self._session = session
        self._model = model

    def latest(self, runs: RunPair) -> int:
        return self._in_run(runs.latest.run_id)

    def previous(self, runs: RunPair) -> int | None:
        run_id = runs.previous.run_id
        return None if run_id is None else self._in_run(run_id)

    def _in_run(self, run_id: str | None) -> int:
        model = self._model
        statement = (
            select(func.count()).select_from(model).where(model.run_id == run_id)
        )
        return self._session.execute(statement).scalar() or 0


class StreamingCount:
    """Rows a streaming collector wrote, counted over an
    ``event_timestamp`` window since streaming tables span sessions."""

    def __init__(self, session: Session, model: type[_RowBase]) -> None:
        self._session = session
        self._model = model

    def latest(self, runs: RunPair) -> int:
        stamp = self._model.event_timestamp
        return self._count((stamp >= runs.latest.started,))

    def previous(self, runs: RunPair) -> int | None:
        if runs.previous.started is None:
            return None
        stamp = self._model.event_timestamp
        return self._count(
            (stamp >= runs.previous.started, stamp < runs.latest.started)
        )

    def _count(self, window: tuple[Any, ...]) -> int:
        statement = select(func.count()).select_from(self._model).where(*window)
        return self._session.execute(statement).scalar() or 0


class RowCounts:
    """Per-collector row counts for the latest run, with a change signal vs
    the previous run."""

    STREAMING = frozenset(item.name for item in Slices.ALL if item.streaming)

    def __init__(self, session: Session) -> None:
        self._session = session

    def for_runs(self, latest: RunMark, previous: RunMark) -> list[dict[str, Any]]:
        runs = RunPair(latest, previous)
        present = SchemaProbe(self._session).tables()
        models = CollectorTables().models().items()
        counts = [
            self._entry(name, model, runs)
            for name, model in models
            if model.__tablename__ in present
        ]
        return sorted(counts, key=self._rows, reverse=True)

    def _rows(self, entry: dict[str, Any]) -> int:
        return entry["rows"]

    def _entry(self, name: str, model: type[_RowBase], runs: RunPair) -> dict[str, Any]:
        counter = self._counter(name, model)
        current, before = counter.latest(runs), counter.previous(runs)
        delta = None if before is None else current - before
        is_new = before == 0 and current > 0 if before is not None else False
        return {"name": name, "rows": current, "delta": delta, "is_new": is_new}

    def _counter(self, name: str, model: type[_RowBase]) -> RunCounter:
        if name in self.STREAMING:
            return StreamingCount(self._session, model)
        return SnapshotCount(self._session, model)
