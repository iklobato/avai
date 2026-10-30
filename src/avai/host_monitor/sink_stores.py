"""The stores behind :class:`~avai.host_monitor.sink.Sink`, one per kind of
data the monitor reads and writes."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sqlalchemy import Engine, Select, exists, func, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from .enums import BehaviorKind, FeedbackLabel, Verdict
from .judge import Judgment
from .models import (
    CollectionRun,
    CollectorErrorRow,
    DnsQueryRow,
    FeedbackRow,
    Judgement,
    ListeningPortRow,
    NetworkConnectionRow,
    NetworkFlowRow,
    ProcessExecRow,
    ProcessRow,
    StreamingSession,
    _RowBase,
)
from .runtime import Clock

if TYPE_CHECKING:
    from .collectors import Collector

NON_BENIGN = (str(Verdict.SUSPICIOUS), str(Verdict.MALICIOUS))


class RunLog:
    """Run lifecycle, row writes and the run-history lookups the judge's
    baseline needs. Keeps no current run: every call names its run."""

    ERROR_MESSAGE_CHARS = 1000

    def __init__(self, engine: Engine, clock: Clock) -> None:
        self._engine = engine
        self._clock = clock

    def start_run(self, hostname: str, lookback_min: int) -> tuple[str, str]:
        run_id, started = str(uuid.uuid4()), self._clock.now_iso()
        run = CollectionRun(
            run_id=run_id,
            started_at=started,
            hostname=hostname,
            lookback_min=lookback_min,
        )
        with Session(self._engine) as session:
            session.add(run)
            session.commit()
        return run_id, started

    def end_run(self, run_id: str, ok: int, failed: int) -> None:
        statement = (
            update(CollectionRun)
            .where(CollectionRun.run_id == run_id)
            .values(
                finished_at=self._clock.now_iso(),
                collectors_ok=ok,
                collectors_failed=failed,
            )
        )
        with Session(self._engine) as session:
            session.execute(statement)
            session.commit()

    def write(self, model: type[_RowBase], rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        with Session(self._engine) as session:
            session.execute(sqlite_insert(model), rows)
            session.commit()

    def write_error(self, run_id: str, collector: str, exc: BaseException) -> None:
        error = CollectorErrorRow(
            run_id=run_id,
            collector=collector,
            error_class=type(exc).__name__,
            message=str(exc)[: self.ERROR_MESSAGE_CHARS],
            occurred_at=self._clock.now_iso(),
        )
        with Session(self._engine) as session:
            session.add(error)
            session.commit()

    def unjudged(self, run_id: str, collector: Collector) -> list[dict[str, Any]]:
        """One entry per distinct, unjudged content_hash for ``run_id``
        (judge_fields drive what's selected)."""
        if not collector.judge_fields:
            return []
        return self._unjudged(collector, collector.model.run_id == run_id)

    def unjudged_all(self, collector: Collector) -> list[dict[str, Any]]:
        """Same as ``unjudged`` but with no run filter: streaming rows
        accumulate between snapshot runs, so each cycle judges whatever
        content_hashes streamed in since."""
        if not collector.judge_fields:
            return []
        return self._unjudged(collector, None)

    def _unjudged(self, collector: Collector, run_filter: Any) -> list[dict[str, Any]]:
        model = collector.model
        names = ["content_hash", *collector.judge_fields]
        judged = exists().where(
            Judgement.content_hash == model.content_hash,
            Judgement.collector == collector.name,
        )
        conditions = [model.content_hash.is_not(None), ~judged]
        conditions = conditions if run_filter is None else [run_filter, *conditions]
        columns = [getattr(model, name) for name in names]
        statement = select(*columns).distinct().where(*conditions)
        with Session(self._engine) as session:
            return [dict(zip(names, row)) for row in session.execute(statement).all()]

    def completed_run_count(self) -> int:
        """Number of snapshot runs that have finished. The in-progress run is
        excluded, so this reflects the history the host had *before* the
        current cycle."""
        statement = (
            select(func.count())
            .select_from(CollectionRun)
            .where(CollectionRun.finished_at.is_not(None))
        )
        with Session(self._engine) as session:
            return int(session.execute(statement).scalar_one())

    def nth_run_started_at(self, position: int) -> str | None:
        """``started_at`` of the n-th completed run (1-indexed, oldest first),
        or None if fewer exist. Marks the end of the baseline-learning
        window."""
        if position < 1:
            return None
        statement = (
            select(CollectionRun.started_at)
            .where(CollectionRun.finished_at.is_not(None))
            .order_by(CollectionRun.started_at)
            .limit(1)
            .offset(position - 1)
        )
        with Session(self._engine) as session:
            return session.execute(statement).scalar_one_or_none()

    def run_started_ats(self) -> list[str]:
        """Every run's ``started_at`` (including the in-progress run),
        ascending; ISO strings sort lexicographically, so callers can bisect."""
        statement = select(CollectionRun.started_at).order_by(CollectionRun.started_at)
        with Session(self._engine) as session:
            return list(session.execute(statement).scalars())

    def first_seen_map(
        self, model: type[_RowBase], content_hashes: list[str]
    ) -> dict[str, tuple[str, int]]:
        """content_hash -> (earliest retained ``collected_at``, distinct runs
        seen). Queried only for unjudged hashes, so pruning can't fake novelty."""
        if not content_hashes:
            return {}
        statement = (
            select(
                model.content_hash,
                func.min(model.collected_at),
                func.count(func.distinct(model.run_id)),
            )
            .where(model.content_hash.in_(content_hashes))
            .group_by(model.content_hash)
        )
        with Session(self._engine) as session:
            rows = session.execute(statement).all()
        return {content_hash: (first, int(runs)) for content_hash, first, runs in rows}

    def prior_run_started_at(self, run_id: str | None) -> str | None:
        """``started_at`` of the run before ``run_id``, or None for the first
        run. Time-bounds correlation to the previous cycle so PID reuse
        can't pollute it."""
        current = select(CollectionRun.started_at).where(CollectionRun.run_id == run_id)
        with Session(self._engine) as session:
            started = session.execute(current).scalar_one_or_none()
            if started is None:
                return None
            previous = (
                select(CollectionRun.started_at)
                .where(CollectionRun.started_at < started)
                .order_by(CollectionRun.started_at.desc())
                .limit(1)
            )
            return session.execute(previous).scalar_one_or_none()

    def touch_judgments(
        self, collector: str, content_hashes: list[str], seen_at: str
    ) -> None:
        """Set ``last_seen_at`` on the judgments observed this cycle. A
        judgment whose ``last_seen_at`` matches the latest run is still
        present; anything older (or NULL) has gone away."""
        if not content_hashes:
            return
        statement = (
            update(Judgement)
            .where(Judgement.collector == collector)
            .where(Judgement.content_hash.in_(content_hashes))
            .values(last_seen_at=seen_at)
        )
        with Session(self._engine) as session:
            session.execute(statement)
            session.commit()

    def start_streaming_session(self, collector: str, hostname: str) -> str:
        run_id = str(uuid.uuid4())
        streaming = StreamingSession(
            run_id=run_id,
            collector=collector,
            hostname=hostname,
            started_at=self._clock.now_iso(),
        )
        with Session(self._engine) as session:
            session.add(streaming)
            session.commit()
        return run_id

    def end_streaming_session(self, run_id: str | None, row_count: int) -> None:
        statement = (
            update(StreamingSession)
            .where(StreamingSession.run_id == run_id)
            .values(finished_at=self._clock.now_iso(), row_count=row_count)
        )
        with Session(self._engine) as session:
            session.execute(statement)
            session.commit()


@dataclass(frozen=True)
class CorrelationWindow:
    """How far back correlation looks (``since``, None for all history) and
    how many items per PID or name it keeps."""

    since: str | None
    per_pid_cap: int = 10

    def bounded(self, statement: Select[Any], model: type[_RowBase]) -> Select[Any]:
        if not self.since:
            return statement
        return statement.where(model.collected_at >= self.since)


class BehaviorReader:
    """What processes did: listening ports, outbound flows, established
    remote connections, DNS queries (by process *name*, which is all DNS
    capture records) and exec lineage."""

    # DNS is keyed by process name, which groups every PID sharing it.
    EXTRA_DNS_PER_NAME = 5

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def pids_by_executable(
        self, executables: list[str], since: str | None = None
    ) -> dict[str, set[int]]:
        """Each executable path mapped to the PIDs running it at/after
        ``since``, so a launch item's ``program`` resolves to the process it
        spawned."""
        if not executables:
            return {}
        statement = select(ProcessRow.exe, ProcessRow.pid).where(
            ProcessRow.exe.in_(executables)
        )
        statement = CorrelationWindow(since).bounded(statement, ProcessRow)
        with Session(self._engine) as session:
            rows = session.execute(statement).all()
        running: dict[str, set[int]] = {}
        for exe, pid in rows:
            if exe and pid is not None:
                running.setdefault(exe, set()).add(pid)
        return running

    def correlation_context(
        self, pids: list[int], proc_names: list[str], window: CorrelationWindow
    ) -> dict[str, dict[Any, Any]]:
        """A PID's recent runtime behaviour for the judge, bounded to rows
        collected at/after ``window.since``. ProcessCollector runs first in a
        cycle, so this deliberately surfaces the *previous* cycle's behaviour
        for a still-running PID."""
        context: dict[str, dict[Any, Any]] = {kind: {} for kind in BehaviorKind}
        live_pids = [pid for pid in pids if pid is not None]
        names = [name for name in proc_names if name]
        with Session(self._engine) as session:
            queries = BehaviorQueries(session, window)
            if live_pids:
                context.update(queries.by_pid(live_pids))
            if names:
                context[BehaviorKind.DNS] = queries.dns(names, self.EXTRA_DNS_PER_NAME)
        return context


class BehaviorQueries:
    """The per-kind behaviour queries, run inside one session."""

    def __init__(self, session: Session, window: CorrelationWindow) -> None:
        self._session = session
        self._window = window

    def by_pid(self, pids: list[int]) -> dict[str, dict[Any, Any]]:
        cap = self._window.per_pid_cap
        return {
            BehaviorKind.PORTS: self._capped(self._listening_ports(pids), cap),
            BehaviorKind.FLOWS: self._capped(self._outbound_flows(pids), cap),
            BehaviorKind.CONNS: self._capped(self._remote_conns(pids), cap),
            BehaviorKind.EXEC: self._latest_execs(pids),
        }

    def dns(self, names: list[str], extra: int) -> dict[Any, list[Any]]:
        model = DnsQueryRow
        statement = select(model.process, model.qname, model.qtype).where(
            model.process.in_(names)
        )
        rows = self._session.execute(self._window.bounded(statement, model))
        pairs = ((process, f"{qname} ({qtype})") for process, qname, qtype in rows)
        return self._capped(pairs, self._window.per_pid_cap + extra)

    def _capped(
        self, pairs: Iterable[tuple[Any, Any]], cap: int
    ) -> dict[Any, list[Any]]:
        """Group (key, value) pairs into per-key lists of at most ``cap``."""
        grouped: dict[Any, list[Any]] = {}
        for key, value in pairs:
            values = grouped.setdefault(key, [])
            if len(values) < cap:
                values.append(value)
        return grouped

    def _listening_ports(self, pids: list[int]) -> Iterator[tuple[int, str]]:
        model = ListeningPortRow
        statement = select(model.pid, model.laddr_ip, model.laddr_port).where(
            model.pid.in_(pids)
        )
        rows = self._session.execute(self._window.bounded(statement, model))
        yield from ((pid, f"{ip}:{port}") for pid, ip, port in rows)

    def _outbound_flows(self, pids: list[int]) -> Iterator[tuple[int, dict[str, Any]]]:
        model = NetworkFlowRow
        statement = select(
            model.pid, model.dst_ip, model.dst_port, model.service, model.packets
        ).where(model.pid.in_(pids))
        statement = self._window.bounded(statement, model).order_by(
            model.packets.desc()
        )
        for pid, ip, port, service, packets in self._session.execute(statement):
            yield pid, {"dst": f"{ip}:{port}", "service": service, "packets": packets}

    def _remote_conns(self, pids: list[int]) -> Iterator[tuple[int, str]]:
        model = NetworkConnectionRow
        statement = select(
            model.pid, model.raddr_ip, model.raddr_port, model.status
        ).where(model.pid.in_(pids), model.raddr_ip.is_not(None))
        rows = self._session.execute(self._window.bounded(statement, model))
        yield from ((pid, f"{ip}:{port} {status}") for pid, ip, port, status in rows)

    def _latest_execs(self, pids: list[int]) -> dict[int, dict[str, Any]]:
        model = ProcessExecRow
        statement = select(
            model.pid, model.parent_path, model.signing_id, model.exe_path
        ).where(model.pid.in_(pids))
        statement = self._window.bounded(statement, model).order_by(
            model.event_timestamp.desc()
        )
        latest: dict[int, dict[str, Any]] = {}
        for pid, parent, signing, exe in self._session.execute(statement):
            latest.setdefault(pid, {"parent": parent, "signed": signing, "exe": exe})
        return latest


class JudgmentStore:
    """Verdicts: writing them, reading the active and recent non-benign
    ones, and applying operator feedback."""

    REASONING_CHARS = 500
    FEEDBACK_EXAMPLES = 10
    RECENT_NONBENIGN = 15
    # Operator feedback label -> the verdict pinned on the corrected finding.
    FEEDBACK_VERDICTS = (
        (FeedbackLabel.FALSE_POSITIVE.value, str(Verdict.BENIGN)),
        (FeedbackLabel.CONFIRMED.value, str(Verdict.MALICIOUS)),
    )

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def write_judgments(
        self,
        judgments: list[Judgment],
        context: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        """Persist judgments. ``context`` maps content_hash to the
        ``baseline`` and/or ``related`` signals computed at judge time, so
        the dashboard can show them on the finding."""
        if not judgments:
            return
        signals = context or {}
        rows = [
            JudgmentRow(judgment).values(signals.get(judgment.content_hash) or {})
            for judgment in judgments
        ]
        with Session(self._engine) as session:
            session.execute(sqlite_insert(Judgement).on_conflict_do_nothing(), rows)
            session.commit()

    def active_findings(self, started: str) -> list[dict[str, Any]]:
        """Non-benign judgments still present as of the current run
        (``last_seen_at == started``), oldest first so a narrative reads as a
        timeline."""
        names = (
            "content_hash", "collector", "verdict", "category",
            "confidence", "reasoning", "remediation", "created_at",
        )  # fmt: skip
        statement = (
            select(*(getattr(Judgement, name) for name in names))
            .where(Judgement.verdict.in_(NON_BENIGN), Judgement.last_seen_at == started)
            .order_by(Judgement.created_at)
        )
        keys = (*names[:-1], "first_flagged")
        with Session(self._engine) as session:
            return [dict(zip(keys, row)) for row in session.execute(statement).all()]

    def apply_feedback(self) -> int:
        """Apply each not-yet-applied operator correction to its finding's
        verdict and mark it applied. Idempotent; a row whose finding no
        longer exists updates nothing but is still marked. Returns the
        number processed."""
        with Session(self._engine) as session:
            pending = (
                session.execute(select(FeedbackRow).where(FeedbackRow.applied == 0))
                .scalars()
                .all()
            )
            for feedback in pending:
                self._correct(session, feedback)
                feedback.applied = 1
            session.commit()
        return len(pending)

    def _correct(self, session: Session, feedback: FeedbackRow) -> None:
        verdict = dict(self.FEEDBACK_VERDICTS).get(feedback.label)
        if verdict is None:
            return
        reasoning = f"[operator: {feedback.label}]"
        reasoning = f"{reasoning} {feedback.note}" if feedback.note else reasoning
        session.execute(
            update(Judgement)
            .where(
                Judgement.content_hash == feedback.content_hash,
                Judgement.collector == feedback.collector,
            )
            .values(
                verdict=verdict,
                confidence=1.0,
                reasoning=reasoning[: self.REASONING_CHARS],
            )
        )

    def feedback_examples(
        self, collector: str, limit: int = FEEDBACK_EXAMPLES
    ) -> list[dict[str, Any]]:
        """Recent operator corrections for a collector: host-specific ground
        truth the judge is shown."""
        statement = (
            select(FeedbackRow.artifact, FeedbackRow.label, FeedbackRow.note)
            .where(FeedbackRow.collector == collector)
            .order_by(FeedbackRow.created_at.desc())
            .limit(limit)
        )
        keys = ("artifact", "label", "note")
        with Session(self._engine) as session:
            return [dict(zip(keys, row)) for row in session.execute(statement).all()]

    def recent_nonbenign(self, limit: int = RECENT_NONBENIGN) -> list[dict[str, Any]]:
        """Most recent non-benign judgments: what else is flagged here."""
        names = ("content_hash", "collector", "verdict", "category", "reasoning")
        statement = (
            select(*(getattr(Judgement, name) for name in names))
            .where(Judgement.verdict.in_(NON_BENIGN))
            .order_by(Judgement.created_at.desc())
            .limit(limit)
        )
        with Session(self._engine) as session:
            return [dict(zip(names, row)) for row in session.execute(statement).all()]


class JudgmentRow:
    """One judgment as the row ``write_judgments`` inserts."""

    def __init__(self, judgment: Judgment) -> None:
        self._judgment = judgment

    def values(self, signals: dict[str, Any]) -> dict[str, Any]:
        judgment = self._judgment
        return {
            "content_hash": judgment.content_hash,
            "collector": judgment.collector,
            "verdict": str(judgment.verdict),
            "category": str(judgment.category),
            "confidence": judgment.confidence,
            "reasoning": judgment.reasoning,
            "remediation": judgment.remediation,
            "remediation_plain": judgment.remediation_plain or None,
            "verify_outcome": judgment.verify_outcome,
            "model": judgment.model,
            "created_at": judgment.created_at,
            "novel": self._novel(signals.get("baseline") or {}),
            "context_json": json.dumps(signals) if signals else None,
            "cost_usd": judgment.cost_usd or None,
        }

    def _novel(self, baseline: dict[str, Any]) -> int | None:
        if not baseline:
            return None
        return 1 if baseline.get("novel") else 0
