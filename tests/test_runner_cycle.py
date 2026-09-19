"""Characterization tests for whole Runner cycles, through public methods only.

They pin what one ``run_once`` / ``run_forever`` does end to end (rows,
verdicts, the context the judge sees, reports, maintenance commands), so the
Runner can be split into smaller parts without changing behaviour.
"""

from __future__ import annotations

import threading
import time

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from avai.enrichers import (
    Enricher,
    EnrichmentChain,
    Evidence,
    EvidenceCache,
    IndicatorType,
    VerdictHint,
)
from avai.host_monitor.enums import ThreatCategory, Verdict
from avai.host_monitor.judge import Judgment, NullJudge
from avai.host_monitor.models import (
    AuthEventRow,
    Base,
    CollectionRun,
    CollectorErrorRow,
    ControlState,
    FeedbackRow,
    IncidentNarrativeRow,
    Judgement,
    NetworkConnectionRow,
    ProcessRow,
    RiskScoreRow,
    YaraCoverageRow,
)
from avai.host_monitor.runner import Runner
from avai.host_monitor.sink import Sink
from avai.host_monitor.runner import RunnerConfig
from avai.host_monitor.runtime import Digest

PROC_FIELDS = ("name", "exe")
AUTH_FIELDS = ("process", "event_message")


@pytest.fixture
def sink():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        # One shared connection, so streaming worker threads see the same db.
        poolclass=StaticPool,
    )
    s = Sink(engine)
    s.setup()
    return s


def _runner(sink, snapshot=(), streaming=(), judge=None, **options) -> Runner:
    return Runner(
        RunnerConfig(
            sink,
            list(snapshot),
            list(streaming),
            judge or NullJudge(),
            5,
            **options,
        )
    )


def _proc_hash(name: str) -> str:
    return Digest.of_row({"name": name, "exe": f"/bin/{name}"}, PROC_FIELDS)


class _Procs:
    name = "processes"
    model = ProcessRow
    judge_enabled = True
    judge_fields = PROC_FIELDS
    judge_hints = "static hint"

    def __init__(self, *names):
        self._names = names

    def collect(self):
        return [
            {"pid": 100 + i, "name": n, "exe": f"/bin/{n}"}
            for i, n in enumerate(self._names)
        ]


class _Conns:
    name = "network_connections"
    model = NetworkConnectionRow
    judge_enabled = True
    judge_fields = ("raddr_ip", "raddr_port", "pid")
    judge_hints = ""

    def collect(self):
        return [
            {
                "raddr_ip": "8.8.8.8",
                "raddr_port": 53,
                "pid": 1,
                "status": "ESTABLISHED",
            }
        ]


class _Broken:
    name = "broken"
    model = ProcessRow
    judge_enabled = False
    judge_fields = ()
    judge_hints = ""

    def collect(self):
        raise OSError("tool missing")


class _Scanner:
    """A file-scan-like collector that exposes a ruleset summary."""

    name = "file_scan_stub"
    model = ProcessRow
    judge_enabled = False
    judge_fields = ()
    judge_hints = ""
    compile_stats = {
        "rules_loaded": 3,
        "files_loaded": 3,
        "files_skipped": 0,
        "rules_dir": "/rules",
        "sources": {"bundled": 3},
        "skip_reasons": {},
        "by_category": {"gen": 3},
        "inventory": [],
    }

    def collect(self):
        return []


class _Tripwire:
    """Requests shutdown while collecting, so run_forever stops after one cycle."""

    model = ProcessRow
    judge_enabled = False
    judge_fields = ()
    judge_hints = ""
    name = "tripwire"

    def __init__(self):
        self.runner = None
        self.runs = 0

    def collect(self):
        self.runs += 1
        self.runner.request_shutdown()
        return []


class _AuthStream:
    name = "auth_events"
    model = AuthEventRow
    judge_enabled = True
    judge_fields = AUTH_FIELDS
    judge_hints = ""

    def __init__(self, rows=()):
        self._rows = rows

    def stream(self, stop_event):
        yield from (dict(r) for r in self._rows)


class _ScriptedJudge:
    """Returns a judgment per entry, with the verdict scripted per artifact."""

    def __init__(self, verdicts=None, default=Verdict.BENIGN):
        self.verdicts = verdicts or {}
        self.default = default
        self.calls: list[tuple[str, str, list[dict]]] = []

    def judge(self, collector, hints, entries):
        self.calls.append((collector, hints, [dict(e) for e in entries]))
        return [
            Judgment(
                content_hash=e["content_hash"],
                collector=collector,
                verdict=self.verdicts.get(
                    e.get("name") or e.get("process"), self.default
                ),
                category=ThreatCategory.PERSISTENCE,
                confidence=0.9,
                reasoning="judge reason",
                remediation="",
                model="m",
                created_at="2026-01-01T00:00:00Z",
            )
            for e in entries
        ]


class _RefutingVerifier:
    def verify(self, finding):
        return {"refuted": True, "reasoning": "signed vendor binary"}


class _ResolvingInvestigator:
    def investigate(self, collector, finding):
        return {
            "verdict": Verdict.BENIGN,
            "category": ThreatCategory.NONE,
            "confidence": 0.7,
            "reasoning": "looked deeper",
            "remediation": "",
        }


class _Narrator:
    model = "narrator-model"

    def __init__(self):
        self.calls = []

    def narrate(self, findings):
        self.calls.append(findings)
        return {
            "headline": "h",
            "severity": "high",
            "summary": "s",
            "timeline": [],
            "actions": [],
        }


class _Assessor:
    model = "coverage-model"

    def __init__(self):
        self.calls = []

    def assess(self, ruleset, host):
        self.calls.append((ruleset, host))
        return {
            "posture": "thin",
            "headline": "h",
            "summary": "s",
            "gaps": [],
            "recommendations": [],
        }


class _HitEnricher(Enricher):
    name = "test_hit"
    supports_types = frozenset({IndicatorType.IPV4})
    requires_token = None

    def _fetch(self, indicator):
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.MALICIOUS,
            confidence=0.9,
            summary="flagged",
        )


def _judgements(sink) -> dict[str, Judgement]:
    with Session(sink.engine) as s:
        return {j.content_hash: j for j in s.scalars(select(Judgement))}


def _set_control(sink, **values):
    from sqlalchemy import update

    sink.ensure_control_row(interval=300, judge_enabled=True, enrich_enabled=True)
    with Session(sink.engine) as s:
        s.execute(update(ControlState).where(ControlState.id == 1).values(**values))
        s.commit()


def _started_at(sink, run_id) -> str:
    with Session(sink.engine) as s:
        return s.get(CollectionRun, run_id).started_at


def _count(sink, model) -> int:
    with Session(sink.engine) as s:
        return s.query(model).count()


class TestSnapshotCycle:
    def test_rows_are_written_judged_and_marked_seen(self, sink):
        judge = _ScriptedJudge({"evil": Verdict.SUSPICIOUS})

        run_id, ok, failed = _runner(
            sink, [_Procs("evil", "good")], judge=judge
        ).run_once()

        assert (ok, failed) == (1, 0)
        with Session(sink.engine) as s:
            rows = s.scalars(select(ProcessRow)).all()
        assert {r.name for r in rows} == {"evil", "good"}
        assert {r.run_id for r in rows} == {run_id}
        judged = _judgements(sink)
        assert judged[_proc_hash("evil")].verdict == "suspicious"
        assert judged[_proc_hash("good")].verdict == "benign"
        started = _started_at(sink, run_id)
        assert {j.last_seen_at for j in judged.values()} == {started}

    def test_judge_sees_baseline_and_operator_feedback(self, sink):
        with Session(sink.engine) as s:
            s.add(
                FeedbackRow(
                    content_hash="old",
                    collector="processes",
                    label="false_positive",
                    artifact="helper",
                    created_at="2026-01-01T00:00:00Z",
                    applied=1,
                )
            )
            s.commit()
        judge = _ScriptedJudge()

        _runner(sink, [_Procs("evil")], judge=judge).run_once()

        collector, hints, entries = judge.calls[0]
        assert collector == "processes"
        assert hints.startswith("static hint")
        assert '"helper" was marked a FALSE POSITIVE' in hints
        assert entries[0]["baseline"]["times_seen"] == 1
        assert entries[0]["baseline"]["novel"] is False

    def test_judge_sees_threat_intel_evidence(self, sink):
        chain = EnrichmentChain([_HitEnricher()], EvidenceCache(sink.engine, Base))
        judge = _ScriptedJudge()

        _runner(sink, [_Conns()], judge=judge, enrichment_chain=chain).run_once()

        evidence = judge.calls[0][2][0]["evidence"]
        assert evidence[0]["src"] == "test_hit"
        assert evidence[0]["value"] == "8.8.8.8"

    def test_second_opinions_rewrite_verdicts_before_they_are_stored(self, sink):
        judge = _ScriptedJudge({"evil": Verdict.MALICIOUS, "odd": Verdict.UNKNOWN})
        runner = _runner(
            sink,
            [_Procs("evil", "odd")],
            judge=judge,
            verifier=_RefutingVerifier(),
            investigator=_ResolvingInvestigator(),
        )

        runner.run_once()

        judged = _judgements(sink)
        assert judged[_proc_hash("evil")].verdict == "suspicious"
        assert "signed vendor binary" in judged[_proc_hash("evil")].reasoning
        assert judged[_proc_hash("odd")].verdict == "benign"
        assert judged[_proc_hash("odd")].reasoning.startswith("[investigated]")

    def test_judging_off_still_marks_known_findings_seen(self, sink):
        with Session(sink.engine) as s:
            s.add(
                Judgement(
                    content_hash=_proc_hash("evil"),
                    collector="processes",
                    verdict="suspicious",
                    model="m",
                    created_at="2026-01-01T00:00:00Z",
                )
            )
            s.commit()
        _set_control(sink, judge_enabled=0)
        judge = _ScriptedJudge()

        run_id, _, _ = _runner(sink, [_Procs("evil", "new")], judge=judge).run_once()

        assert judge.calls == []
        judged = _judgements(sink)
        assert set(judged) == {_proc_hash("evil")}
        assert judged[_proc_hash("evil")].last_seen_at == _started_at(sink, run_id)

    def test_a_failing_collector_is_recorded_and_the_cycle_goes_on(self, sink):
        run_id, ok, failed = _runner(sink, [_Broken(), _Procs("a")]).run_once()

        assert (ok, failed) == (1, 1)
        with Session(sink.engine) as s:
            error = s.scalars(select(CollectorErrorRow)).one()
        assert (error.run_id, error.collector) == (run_id, "broken")
        assert error.error_class == "OSError"


def _stream_row(process, message):
    row = {"process": process, "event_message": message}
    return {
        **row,
        "run_id": "stream-session",
        "collected_at": "2026-01-01T00:00:00Z",
        "content_hash": Digest.of_row(row, AUTH_FIELDS),
    }


class TestStreamingJudging:
    def test_new_streamed_rows_are_judged_each_cycle(self, sink):
        sink.write(AuthEventRow, [_stream_row("sshd", "failed password")])
        judge = _ScriptedJudge({"sshd": Verdict.SUSPICIOUS})

        _runner(sink, streaming=[_AuthStream()], judge=judge).run_once()

        collector, _, entries = judge.calls[0]
        assert collector == "auth_events"
        assert entries[0]["baseline"]["times_seen"] == 1
        assert [j.verdict for j in _judgements(sink).values()] == ["suspicious"]

    def test_disabled_streaming_collector_is_not_judged(self, sink):
        sink.write(AuthEventRow, [_stream_row("sshd", "failed password")])
        _set_control(sink, disabled_collectors="auth_events")
        judge = _ScriptedJudge()

        _runner(sink, streaming=[_AuthStream()], judge=judge).run_once()

        assert judge.calls == []

    def test_a_failing_streaming_judge_does_not_fail_the_cycle(self, sink):
        sink.write(AuthEventRow, [_stream_row("sshd", "failed password")])

        class _Exploding(_ScriptedJudge):
            def judge(self, collector, hints, entries):
                raise RuntimeError("llm down")

        _, ok, failed = _runner(
            sink, [_Procs("a")], streaming=[_AuthStream()], judge=_Exploding()
        ).run_once()

        assert (ok, failed) == (
            0,
            1,
        )  # the snapshot judge failed; streaming did not raise


class TestEndOfCycleReports:
    def test_reports_are_written_after_judging(self, sink):
        narrator, assessor = _Narrator(), _Assessor()
        runner = _runner(
            sink,
            [_Procs("evil"), _Scanner()],
            judge=_ScriptedJudge({"evil": Verdict.MALICIOUS}),
            narrator=narrator,
            coverage=assessor,
        )

        runner.run_once()

        assert [f["content_hash"] for f in narrator.calls[0]] == [_proc_hash("evil")]
        assert _count(sink, IncidentNarrativeRow) == 1
        assert _count(sink, RiskScoreRow) == 1
        assert sink.read_yara_status()["rules_loaded"] == 3
        assert assessor.calls[0][1]["hostname"]
        assert _count(sink, YaraCoverageRow) == 1

    def test_risk_score_is_written_without_any_llm(self, sink):
        _runner(sink, [_Procs("a")]).run_once()

        assert _count(sink, RiskScoreRow) == 1
        assert _count(sink, IncidentNarrativeRow) == 0

    def test_database_is_pruned_to_the_size_cap(self, sink, monkeypatch):
        caps = []

        def fake_prune(max_bytes):
            caps.append(max_bytes)
            return {
                "runs_pruned": 1,
                "events_pruned": 0,
                "bytes_before": 2,
                "bytes_after": 1,
            }

        monkeypatch.setattr(sink, "prune_to_size", fake_prune)

        _runner(sink, max_db_bytes=4096).run_once()

        assert caps == [4096]

    def test_no_cap_means_no_pruning(self, sink, monkeypatch):
        monkeypatch.setattr(
            sink, "prune_to_size", lambda b: pytest.fail("pruned without a cap")
        )

        _runner(sink).run_once()


def _run_forever_once(sink, **options) -> _Tripwire:
    tripwire = _Tripwire()
    runner = _runner(sink, [tripwire], **options)
    tripwire.runner = runner
    runner.run_forever(300)
    return tripwire


class TestControlLoopCommands:
    @pytest.mark.parametrize(
        ("command", "result_prefix"),
        [
            ("clear", "cleared "),
            ("rejudge", "cleared "),
            ("renarrate", "cleared "),
            ("reset_baseline", "reset baseline"),
            ("prune", "pruned runs="),
            ("nonsense", "unknown command: nonsense"),
        ],
    )
    def test_command_runs_once_and_is_acknowledged(self, sink, command, result_prefix):
        _set_control(sink, command=command, command_nonce=4, command_applied=0)

        tripwire = _run_forever_once(sink)

        control = sink.read_control()
        assert control["command_applied"] == 4
        assert control["command_result"].startswith(result_prefix)
        assert tripwire.runs == 1

    def test_a_failing_command_is_acknowledged_with_the_error(self, sink, monkeypatch):
        def boom():
            raise RuntimeError("disk full")

        monkeypatch.setattr(sink, "clear_data", boom)
        _set_control(sink, command="clear", command_nonce=1, command_applied=0)

        _run_forever_once(sink)

        assert sink.read_control()["command_result"] == (
            "error: RuntimeError: disk full"
        )

    def test_a_failed_cycle_does_not_stop_the_loop(self, sink, monkeypatch):
        tripwire = _Tripwire()
        runner = _runner(sink, [tripwire])
        tripwire.runner = runner

        def failing_end_run(ok, failed):
            raise RuntimeError("db locked")

        monkeypatch.setattr(sink, "end_run", failing_end_run)

        runner.run_forever(300)  # must return, not raise

        assert tripwire.runs == 1


class TestStreamingWorkers:
    def test_workers_write_streamed_rows_and_stop(self, sink):
        runner = _runner(
            sink,
            streaming=[_AuthStream([_stream_row("sshd", "a"), _stream_row("su", "b")])],
        )

        runner.start_streaming()
        deadline = time.monotonic() + 5
        while _count(sink, AuthEventRow) < 2 and time.monotonic() < deadline:
            time.sleep(0.05)
        runner.stop_streaming()

        assert _count(sink, AuthEventRow) == 2
        assert [
            t.name for t in threading.enumerate() if t.name.startswith("stream-")
        ] == []

    def test_no_streaming_collectors_starts_nothing(self, sink):
        runner = _runner(sink)

        runner.start_streaming()
        runner.stop_streaming()

        assert _count(sink, AuthEventRow) == 0
