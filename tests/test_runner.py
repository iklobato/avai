"""Tests for the Runner — specifically its enrichment-phase wiring
(``_enrich_entries``) and the cycle's overall sequencing.

The full ``Runner.run_once`` pulls in the collector factory which
needs platform-specific binaries, so we don't drive it end-to-end
here. Instead we build a Runner with hand-rolled fakes and exercise
just the methods that mediate enrichment + judging.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from avai.enrichers import (
    Enricher,
    EnrichmentChain,
    Evidence,
    EvidenceCache,
    Indicator,
    IndicatorType,
    VerdictHint,
)
from avai.host_monitor import (
    DEFAULT_BASELINE_MIN_RUNS,
    Base,
    CollectionRun,
    NullJudge,
    ProcessRow,
    Runner,
    Sink,
    content_hash,
    utcnow,
)


class _StubCollector:
    name = "processes"
    model = ProcessRow
    judge_enabled = True
    judge_fields = ("name", "exe")
    judge_hints = ""


class _RecordingJudge:
    """Captures every (collector, entries) pair the Runner passes to it."""

    def __init__(self):
        self.calls: list[tuple[str, list[dict]]] = []

    def judge(self, collector_name, hints, entries):
        self.calls.append((collector_name, list(entries)))
        return []


class _AlwaysHitEnricher(Enricher):
    name = "test_hit"
    supports_types = frozenset({IndicatorType.SHA256, IndicatorType.IPV4})
    requires_token = None

    def __init__(self):
        self.calls: list[Indicator] = []

    def _fetch(self, indicator: Indicator):
        self.calls.append(indicator)
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.MALICIOUS,
            confidence=0.9,
            summary=f"test malicious hit for {indicator.value}",
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sink():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    s = Sink(engine)
    s.setup()
    return s


@pytest.fixture
def chain(sink):
    return EnrichmentChain([_AlwaysHitEnricher()], EvidenceCache(sink.engine, Base))


# ---------------------------------------------------------------------------
# Runner._enrich_entries — the wiring code
# ---------------------------------------------------------------------------


class TestEnrichEntries:
    def _runner(self, sink, judge, chain):
        return Runner(
            sink=sink,
            snapshot_collectors=[],
            streaming_collectors=[],
            judge=judge,
            lookback_min=5,
            enrichment_chain=chain,
        )

    def test_attaches_evidence_to_each_unjudged_entry(self, sink, chain):
        runner = self._runner(sink, _RecordingJudge(), chain)
        # Two distinct hashes — the chain enriches each via an indicator
        # extracted from `network_connections`. Build rows directly.
        from avai.host_monitor import NetworkConnectionRow

        collector = _StubCollector()
        collector.name = "network_connections"
        collector.model = NetworkConnectionRow
        collector.judge_fields = ("raddr", "pid", "proc_name")

        rows = [
            {
                "raddr": "8.8.8.8:53",
                "pid": 1,
                "proc_name": "dns",
                "username": "u",
                "status": "ESTABLISHED",
                "run_id": "x",
                "collected_at": utcnow(),
                "content_hash": content_hash(
                    {"raddr": "8.8.8.8:53", "pid": 1, "proc_name": "dns"},
                    collector.judge_fields,
                ),
            }
        ]
        unjudged = [
            {
                "content_hash": rows[0]["content_hash"],
                "raddr": "8.8.8.8:53",
                "pid": 1,
                "proc_name": "dns",
            }
        ]

        n = runner._enrich_entries(collector, unjudged, rows)
        assert n == 1  # one indicator extracted (8.8.8.8)
        assert "evidence" in unjudged[0]
        assert any(e["src"] == "test_hit" for e in unjudged[0]["evidence"])
        assert unjudged[0]["evidence"][0]["hint"] == "malicious"

    def test_no_chain_means_no_evidence_no_lookups(self, sink):
        runner = Runner(sink, [], [], _RecordingJudge(), 5, enrichment_chain=None)
        from avai.host_monitor import NetworkConnectionRow

        collector = _StubCollector()
        collector.name = "network_connections"
        collector.model = NetworkConnectionRow
        collector.judge_fields = ("raddr",)

        rows = [{"raddr": "8.8.8.8:53"}]
        unjudged = [{"content_hash": "x", "raddr": "8.8.8.8:53"}]
        n = runner._enrich_entries(collector, unjudged, rows)
        assert n == 0
        assert "evidence" not in unjudged[0]

    def test_no_indicators_means_no_evidence_field(self, sink, chain):
        runner = self._runner(sink, _RecordingJudge(), chain)
        # "Unknown" collector has no extractor → no indicators → no
        # evidence field added to the entry.
        collector = _StubCollector()
        collector.name = "no_extractor_for_this_collector"
        unjudged = [{"content_hash": "x", "name": "irrelevant"}]
        n = runner._enrich_entries(collector, unjudged, [{}])
        assert n == 0
        assert "evidence" not in unjudged[0]

    def test_entry_without_matching_row_is_skipped_cleanly(self, sink, chain):
        runner = self._runner(sink, _RecordingJudge(), chain)
        from avai.host_monitor import NetworkConnectionRow

        collector = _StubCollector()
        collector.name = "network_connections"
        collector.model = NetworkConnectionRow
        collector.judge_fields = ("raddr",)
        unjudged = [{"content_hash": "never-seen", "raddr": "x"}]
        rows = [{"content_hash": "different-hash", "raddr": "8.8.8.8:53"}]
        n = runner._enrich_entries(collector, unjudged, rows)
        assert n == 0
        assert "evidence" not in unjudged[0]

    def test_broken_enricher_does_not_break_cycle(self, sink):
        """A source that raises must not break the per-entry loop."""

        class _Broken(Enricher):
            name = "broken"
            supports_types = frozenset({IndicatorType.IPV4})
            requires_token = None

            def _fetch(self, indicator):
                raise RuntimeError("intentional")

        cache = EvidenceCache(sink.engine, Base)
        chain = EnrichmentChain([_Broken()], cache)
        runner = Runner(sink, [], [], _RecordingJudge(), 5, enrichment_chain=chain)
        from avai.host_monitor import NetworkConnectionRow

        collector = _StubCollector()
        collector.name = "network_connections"
        collector.model = NetworkConnectionRow
        collector.judge_fields = ("raddr",)
        h = content_hash({"raddr": "8.8.8.8:53"}, collector.judge_fields)
        rows = [{"raddr": "8.8.8.8:53", "content_hash": h}]
        unjudged = [{"content_hash": h, "raddr": "8.8.8.8:53"}]
        # Should not raise; broken source counts as an error in stats.
        n = runner._enrich_entries(collector, unjudged, rows)
        assert n == 1
        # No evidence attached (the only source errored).
        assert unjudged[0].get("evidence") in (None, [])
        # The chain recorded the error.
        assert chain.stats()["broken"]["error"] == 1


class _CountingCollector:
    """Records each collect() call; can trip the runner's shutdown
    while collecting to simulate Ctrl-C mid-cycle."""

    model = ProcessRow
    judge_enabled = False
    judge_fields = ()
    judge_hints = ""

    def __init__(self, name, runner_ref=None, trip=False):
        self.name = name
        self._runner_ref = runner_ref
        self._trip = trip

    def collect(self):
        _CountingCollector.calls.append(self.name)
        if self._trip and self._runner_ref["r"] is not None:
            self._runner_ref["r"].request_shutdown()
        return []


class TestShutdownResponsiveness:
    """run_once must honour a shutdown request mid-cycle so Ctrl-C
    takes effect during a long LLM-judging cycle instead of running
    every remaining collector first."""

    def test_no_collectors_run_when_shutdown_already_set(self, sink):
        _CountingCollector.calls = []
        c1 = _CountingCollector("a")
        c2 = _CountingCollector("b")
        runner = Runner(sink, [c1, c2], [], NullJudge(), 5)
        runner.request_shutdown()  # Ctrl-C before the loop starts
        run_id, ok, failed = runner.run_once()
        assert _CountingCollector.calls == []  # loop broke immediately
        assert ok == 0

    def test_stops_after_collector_that_trips_shutdown(self, sink):
        _CountingCollector.calls = []
        ref = {"r": None}
        c1 = _CountingCollector("a", runner_ref=ref, trip=True)
        c2 = _CountingCollector("b")
        c3 = _CountingCollector("c")
        runner = Runner(sink, [c1, c2, c3], [], NullJudge(), 5)
        ref["r"] = runner  # c1 trips shutdown while collecting
        runner.run_once()
        # c1 runs fully; the pre-loop check then breaks before c2/c3.
        assert _CountingCollector.calls == ["a"]


# ---------------------------------------------------------------------------
# Per-host baseline / novelty signal
# ---------------------------------------------------------------------------

# Fixed, increasing ISO timestamps — lexicographic order == chronological,
# which is what the baseline queries rely on.
_TS = [f"2026-01-01T00:{m:02d}:00Z" for m in range(1, 20)]


def _add_run(sink, started_at, finished=True):
    with Session(sink.engine) as s:
        s.add(
            CollectionRun(
                run_id=started_at,  # timestamp doubles as a unique id here
                started_at=started_at,
                finished_at=started_at if finished else None,
                hostname="h",
                lookback_min=5,
            )
        )
        s.commit()


def _add_proc(sink, run_id, collected_at, name):
    h = content_hash({"name": name}, ("name",))
    sink.write(
        ProcessRow,
        [
            {
                "pid": 1,
                "name": name,
                "run_id": run_id,
                "collected_at": collected_at,
                "content_hash": h,
            }
        ],
    )
    return h


class _ProcStub:
    name = "processes"
    model = ProcessRow
    judge_enabled = True
    judge_fields = ("name",)
    judge_hints = ""


class TestHostBaseline:
    def _runner(self, sink, min_runs):
        return Runner(sink, [], [], NullJudge(), 5, baseline_min_runs=min_runs)

    def test_not_established_below_threshold(self, sink):
        _add_run(sink, _TS[0])
        _add_run(sink, _TS[1])
        bl = self._runner(sink, 3)._host_baseline()
        assert bl == {"total_runs": 2, "established": False, "cutoff_at": None}

    def test_established_at_threshold_sets_cutoff_to_nth_run(self, sink):
        _add_run(sink, _TS[0])
        _add_run(sink, _TS[1])
        _add_run(sink, _TS[2])
        bl = self._runner(sink, 3)._host_baseline()
        assert bl["established"] is True
        assert bl["total_runs"] == 3
        assert bl["cutoff_at"] == _TS[2]  # started_at of the 3rd completed run

    def test_in_progress_run_not_counted(self, sink):
        # Two finished + one still running: only the finished ones count,
        # so a min_runs=3 host is still being learned.
        _add_run(sink, _TS[0])
        _add_run(sink, _TS[1])
        _add_run(sink, _TS[2], finished=False)
        bl = self._runner(sink, 3)._host_baseline()
        assert bl["established"] is False
        assert bl["total_runs"] == 2

    def test_default_threshold_constant_is_used(self, sink):
        # No explicit override → the documented default applies.
        r = Runner(sink, [], [], NullJudge(), 5)
        assert r.baseline_min_runs == DEFAULT_BASELINE_MIN_RUNS


class TestFirstSeenMap:
    def test_first_seen_and_times_seen(self, sink):
        # "a" seen in two runs, "b" in one.
        ha = _add_proc(sink, _TS[0], _TS[0], "a")
        _add_proc(sink, _TS[1], _TS[1], "a")
        hb = _add_proc(sink, _TS[2], _TS[2], "b")
        m = sink.first_seen_map(ProcessRow, [ha, hb])
        assert m[ha] == (_TS[0], 2)
        assert m[hb] == (_TS[2], 1)

    def test_empty_input_returns_empty(self, sink):
        assert sink.first_seen_map(ProcessRow, []) == {}


class TestAnnotateBaseline:
    def test_novel_true_for_artifact_first_seen_after_cutoff(self, sink):
        # Establish a baseline of 2 runs; cutoff == 2nd run start (_TS[1]).
        _add_run(sink, _TS[0])
        _add_run(sink, _TS[1])
        h_old = _add_proc(sink, _TS[0], _TS[0], "old")  # pre-baseline
        h_new = _add_proc(sink, _TS[2], _TS[2], "new")  # post-baseline
        runner = Runner(sink, [], [], NullJudge(), 5, baseline_min_runs=2)
        bl = runner._host_baseline()

        unjudged = [
            {"content_hash": h_old, "name": "old"},
            {"content_hash": h_new, "name": "new"},
        ]
        runner._annotate_baseline(_ProcStub(), unjudged, bl)

        old, new = unjudged
        assert old["baseline"]["novel"] is False
        assert old["baseline"]["first_seen"] == _TS[0]
        assert new["baseline"]["novel"] is True
        assert new["baseline"]["first_seen"] == _TS[2]
        assert new["baseline"]["baseline_established"] is True

    def test_nothing_novel_while_host_still_being_learned(self, sink):
        # Only 2 completed runs but threshold is 5 → not established.
        _add_run(sink, _TS[0])
        _add_run(sink, _TS[1])
        h = _add_proc(sink, _TS[2], _TS[2], "x")
        runner = Runner(sink, [], [], NullJudge(), 5, baseline_min_runs=5)
        bl = runner._host_baseline()

        unjudged = [{"content_hash": h, "name": "x"}]
        runner._annotate_baseline(_ProcStub(), unjudged, bl)

        assert unjudged[0]["baseline"]["baseline_established"] is False
        assert unjudged[0]["baseline"]["novel"] is False

    def test_entry_without_matching_row_gets_no_baseline_key(self, sink):
        _add_run(sink, _TS[0])
        _add_run(sink, _TS[1])
        runner = Runner(sink, [], [], NullJudge(), 5, baseline_min_runs=2)
        bl = runner._host_baseline()
        unjudged = [{"content_hash": "never-collected", "name": "ghost"}]
        runner._annotate_baseline(_ProcStub(), unjudged, bl)
        assert "baseline" not in unjudged[0]


# ---------------------------------------------------------------------------
# Process-story correlation
# ---------------------------------------------------------------------------


def _w(sink, model, **cols):
    sink.write(model, [cols])


class TestAttachCorrelation:
    def _setup_two_runs(self, sink):
        # ProcessCollector runs first, so correlation reads the *previous*
        # cycle's network rows. Put them in the prior run (_TS[0]); judge
        # in the current run (_TS[1]) whose prior_run_started_at == _TS[0].
        _add_run(sink, _TS[0])
        _add_run(sink, _TS[1])

    def test_processes_get_full_related_object(self, sink):
        from avai.host_monitor import (
            DnsQueryRow,
            ListeningPortRow,
            NetworkConnectionRow,
            NetworkFlowRow,
            ProcessExecRow,
        )

        self._setup_two_runs(sink)
        _w(
            sink,
            ListeningPortRow,
            pid=42,
            laddr_ip="0.0.0.0",
            laddr_port=4444,
            run_id=_TS[0],
            collected_at=_TS[0],
        )
        _w(
            sink,
            NetworkFlowRow,
            pid=42,
            dst_ip="9.9.9.9",
            dst_port=443,
            service="https",
            packets=120,
            run_id=_TS[0],
            collected_at=_TS[0],
        )
        _w(
            sink,
            NetworkConnectionRow,
            pid=42,
            raddr_ip="9.9.9.9",
            raddr_port=443,
            status="ESTABLISHED",
            run_id=_TS[0],
            collected_at=_TS[0],
        )
        _w(
            sink,
            DnsQueryRow,
            process="evil",
            qname="c2.example",
            qtype="A",
            run_id=_TS[0],
            collected_at=_TS[0],
        )
        _w(
            sink,
            ProcessExecRow,
            pid=42,
            parent_path="/bin/zsh",
            signing_id=None,
            exe_path="/tmp/evil",
            event_timestamp=_TS[0],
            run_id=_TS[0],
            collected_at=_TS[0],
        )

        h = content_hash({"name": "evil"}, ("name",))
        rows = [{"content_hash": h, "pid": 42, "name": "evil"}]
        unjudged = [{"content_hash": h, "name": "evil"}]
        runner = Runner(sink, [], [], NullJudge(), 5)
        runner._attach_correlation(_ProcStub(), unjudged, rows, _TS[1])

        rel = unjudged[0]["related"]
        assert rel["listening_ports"] == ["0.0.0.0:4444"]
        assert rel["outbound_flows"][0]["dst"] == "9.9.9.9:443"
        assert rel["outbound_flows"][0]["packets"] == 120
        assert rel["remote_connections"] == ["9.9.9.9:443 ESTABLISHED"]
        assert rel["dns_queries"] == ["c2.example (A)"]
        assert rel["exec_lineage"] == {
            "parent": "/bin/zsh",
            "signed": None,
            "exe": "/tmp/evil",
        }

    def test_non_process_collector_is_not_correlated(self, sink):
        from avai.host_monitor import ListeningPortRow

        self._setup_two_runs(sink)
        _w(
            sink,
            ListeningPortRow,
            pid=42,
            laddr_ip="0.0.0.0",
            laddr_port=4444,
            run_id=_TS[0],
            collected_at=_TS[0],
        )

        class _PortStub:
            name = "listening_ports"
            model = ListeningPortRow
            judge_fields = ("laddr_port",)
            judge_hints = ""

        rows = [{"content_hash": "h", "pid": 42, "name": "evil"}]
        unjudged = [{"content_hash": "h"}]
        runner = Runner(sink, [], [], NullJudge(), 5)
        runner._attach_correlation(_PortStub(), unjudged, rows, _TS[1])
        assert "related" not in unjudged[0]

    def test_process_with_no_correlated_rows_gets_no_related(self, sink):
        self._setup_two_runs(sink)
        h = content_hash({"name": "quiet"}, ("name",))
        rows = [{"content_hash": h, "pid": 999, "name": "quiet"}]
        unjudged = [{"content_hash": h, "name": "quiet"}]
        runner = Runner(sink, [], [], NullJudge(), 5)
        runner._attach_correlation(_ProcStub(), unjudged, rows, _TS[1])
        assert "related" not in unjudged[0]

    def test_stale_rows_before_prior_run_are_excluded(self, sink):
        # A flow from two cycles ago (_TS[0]) must NOT leak in when judging
        # at _TS[2], whose prior run is _TS[1]: the time-bound is the PID's
        # previous-cycle behaviour only, so PID reuse can't pollute it.
        from avai.host_monitor import NetworkFlowRow

        _add_run(sink, _TS[0])
        _add_run(sink, _TS[1])
        _add_run(sink, _TS[2])
        _w(
            sink,
            NetworkFlowRow,
            pid=42,
            dst_ip="9.9.9.9",
            dst_port=443,
            service="https",
            packets=10,
            run_id=_TS[0],
            collected_at=_TS[0],
        )

        h = content_hash({"name": "evil"}, ("name",))
        rows = [{"content_hash": h, "pid": 42, "name": "evil"}]
        unjudged = [{"content_hash": h, "name": "evil"}]
        runner = Runner(sink, [], [], NullJudge(), 5)
        runner._attach_correlation(_ProcStub(), unjudged, rows, _TS[2])
        assert "related" not in unjudged[0]  # _TS[0] < prior(_TS[2]) == _TS[1]


# ---------------------------------------------------------------------------
# Incident narrative — generation gating + Sink.active_findings
# ---------------------------------------------------------------------------


class _FakeNarrator:
    model = "fake-model"

    def __init__(self, result=None):
        self.calls = []
        self._result = result or {
            "headline": "Unsigned binary beaconing to C2",
            "severity": "high",
            "summary": "A novel /tmp binary opened a flow to a flagged IP.",
            "timeline": [
                {
                    "time": "2026-05-30T18:54",
                    "title": "binary launched",
                    "category": "execution",
                    "detail": "/tmp/x ran",
                },
            ],
            "actions": [
                {
                    "priority": "immediate",
                    "title": "kill it",
                    "command": "kill 123",
                    "detail": "stop the process",
                },
            ],
        }

    def narrate(self, findings):
        self.calls.append(list(findings))
        return self._result


def _add_judgement(
    sink, h, verdict, last_seen, collector="processes", created="2026-01-01T00:00:00Z"
):
    from avai.host_monitor import Judgement

    with Session(sink.engine) as s:
        s.add(
            Judgement(
                content_hash=h,
                collector=collector,
                verdict=verdict,
                category="none",
                confidence=0.9,
                reasoning="r",
                remediation="",
                model="m",
                created_at=created,
                last_seen_at=last_seen,
            )
        )
        s.commit()


class TestJudgmentContext:
    def _judgment(self, h):
        from avai.host_monitor import Judgment, ThreatCategory, Verdict

        return Judgment(
            content_hash=h,
            collector="processes",
            verdict=Verdict.MALICIOUS,
            category=ThreatCategory.PERSISTENCE,
            confidence=0.9,
            reasoning="r",
            remediation="",
            model="m",
            created_at="2026-01-01T00:00:00Z",
        )

    def test_judgment_context_extracts_baseline_and_related(self):
        runner = Runner(None, [], [], NullJudge(), 5)
        unjudged = [
            {
                "content_hash": "h1",
                "baseline": {"novel": True},
                "related": {"listening_ports": ["0.0.0.0:4444"]},
            },
            {"content_hash": "h2"},  # nothing → omitted
            {"baseline": {"novel": False}},  # no hash → skipped
        ]
        ctx = runner._judgment_context(unjudged)
        assert set(ctx) == {"h1"}
        assert ctx["h1"]["baseline"]["novel"] is True
        assert ctx["h1"]["related"]["listening_ports"] == ["0.0.0.0:4444"]

    def test_write_judgments_persists_novel_and_context(self, sink):
        import json as _json

        from avai.host_monitor import Judgement

        ctx = {
            "h1": {
                "baseline": {"novel": True, "first_seen": "t", "times_seen": 3},
                "related": {"listening_ports": ["0.0.0.0:4444"]},
            }
        }
        sink.write_judgments([self._judgment("h1")], context=ctx)
        with Session(sink.engine) as s:
            row = s.get(Judgement, ("h1", "processes"))
        assert row.novel == 1
        parsed = _json.loads(row.context_json)
        assert parsed["baseline"]["novel"] is True
        assert parsed["related"]["listening_ports"] == ["0.0.0.0:4444"]

    def test_write_judgments_without_context_leaves_columns_null(self, sink):
        from avai.host_monitor import Judgement

        sink.write_judgments([self._judgment("h2")])
        with Session(sink.engine) as s:
            row = s.get(Judgement, ("h2", "processes"))
        assert row.novel is None
        assert row.context_json is None


class TestActiveFindings:
    def test_filters_benign_and_resolved(self, sink):
        _add_judgement(sink, "h_mal", "malicious", last_seen=_TS[1])  # active
        _add_judgement(sink, "h_sus", "suspicious", last_seen=_TS[1])  # active
        _add_judgement(sink, "h_ben", "benign", last_seen=_TS[1])  # benign → out
        _add_judgement(sink, "h_old", "malicious", last_seen=_TS[0])  # resolved → out
        active = sink.active_findings(_TS[1])
        hashes = {f["content_hash"] for f in active}
        assert hashes == {"h_mal", "h_sus"}


class TestGenerateNarrative:
    def _runner(self, sink, narrator):
        return Runner(sink, [], [], NullJudge(), 5, narrator=narrator)

    def test_no_active_findings_no_narrative(self, sink):
        nar = _FakeNarrator()
        self._runner(sink, nar)._generate_narrative(_TS[1], _TS[1])
        assert nar.calls == []
        assert sink.latest_narrative_finding_hashes() is None

    def test_active_findings_generate_and_store(self, sink):
        _add_judgement(sink, "h_mal", "malicious", last_seen=_TS[1])
        nar = _FakeNarrator()
        self._runner(sink, nar)._generate_narrative("run-1", _TS[1])
        assert len(nar.calls) == 1
        import json as _json

        nrow = latest_narrative_row(sink)
        assert nrow.severity == "high"
        assert nrow.finding_count == 1
        assert nrow.headline == "Unsigned binary beaconing to C2"
        assert nrow.summary.startswith("A novel")
        assert _json.loads(nrow.timeline_json)[0]["title"] == "binary launched"
        assert _json.loads(nrow.actions_json)[0]["priority"] == "immediate"

    def test_unchanged_findings_are_not_regenerated(self, sink):
        _add_judgement(sink, "h_mal", "malicious", last_seen=_TS[1])
        nar = _FakeNarrator()
        r = self._runner(sink, nar)
        r._generate_narrative("run-1", _TS[1])
        r._generate_narrative("run-1", _TS[1])  # same finding-set
        assert len(nar.calls) == 1  # second call skipped by hash compare

    def test_changed_findings_regenerate(self, sink):
        _add_judgement(sink, "h_mal", "malicious", last_seen=_TS[1])
        nar = _FakeNarrator()
        r = self._runner(sink, nar)
        r._generate_narrative("run-1", _TS[1])
        _add_judgement(sink, "h_sus", "suspicious", last_seen=_TS[1])  # new finding
        r._generate_narrative("run-2", _TS[1])
        assert len(nar.calls) == 2


def latest_narrative_row(sink):
    from avai.host_monitor import IncidentNarrativeRow

    with Session(sink.engine) as s:
        return s.execute(select_desc_incident(IncidentNarrativeRow)).scalars().first()


def select_desc_incident(model):
    from sqlalchemy import desc, select

    return select(model).order_by(desc(model.created_at))


class TestIncidentNarratorNormalization:
    def _narrator(self, payload):
        from avai.host_monitor import DEFAULT_PROMPTS_PATH, IncidentNarrator, Prompts

        class _FakeClient:
            def __init__(self):
                self.calls = []

            def complete_structured(self, **kw):
                self.calls.append(kw)
                return payload

        return IncidentNarrator(
            prompts=Prompts.load(DEFAULT_PROMPTS_PATH), client=_FakeClient()
        )

    def test_bad_severity_falls_back_to_low(self):
        nar = self._narrator(
            {
                "headline": "h",
                "severity": "apocalyptic",
                "summary": "s",
                "timeline": [],
                "actions": [],
            }
        )
        out = nar.narrate([{"content_hash": "x"}])
        assert out["severity"] == "low"

    def test_missing_headline_returns_none(self):
        nar = self._narrator({"severity": "high", "summary": "s", "timeline": []})
        assert nar.narrate([{"content_hash": "x"}]) is None

    def test_returns_none_when_no_summary_and_no_timeline(self):
        nar = self._narrator(
            {
                "headline": "h",
                "severity": "high",
                "summary": "",
                "timeline": [],
                "actions": [],
            }
        )
        assert nar.narrate([{"content_hash": "x"}]) is None

    def test_empty_findings_returns_none_without_calling_llm(self):
        nar = self._narrator({"headline": "h", "severity": "low", "summary": "s"})
        assert nar.narrate([]) is None

    def test_timeline_and_actions_are_normalised(self):
        nar = self._narrator(
            {
                "headline": "h",
                "severity": "high",
                "summary": "s",
                "timeline": [
                    {"title": "kept", "category": "C2", "time": "t", "detail": "d"},
                    {"category": "x"},  # no title → dropped
                ],
                "actions": [
                    {
                        "title": "act",
                        "priority": "bogus",
                        "command": "c",
                    },  # bad prio → medium
                    {"command": "no title"},  # no title → dropped
                ],
            }
        )
        out = nar.narrate([{"content_hash": "x"}])
        assert len(out["timeline"]) == 1
        assert out["timeline"][0]["category"] == "c2"  # lower-cased
        assert len(out["actions"]) == 1
        assert out["actions"][0]["priority"] == "medium"


# ---------------------------------------------------------------------------
# Host risk score
# ---------------------------------------------------------------------------

_HARDENED = {
    "filevault_active": 1,
    "firewall_global_state": 1,
    "gatekeeper_assessments_enabled": 1,
    "firewall_stealth": 1,
    "remote_login_enabled": 0,
    "screen_sharing_enabled": 0,
    "remote_management_enabled": 0,
}


class TestComputeRiskScore:
    def test_hardened_host_scores_100_grade_a(self):
        from avai.host_monitor import compute_risk_score

        r = compute_risk_score(_HARDENED, 0, 0, 0, 0)
        assert r["score"] == 100 and r["grade"] == "A" and r["drivers"] == []

    def test_disabled_protections_deduct(self):
        from avai.host_monitor import compute_risk_score

        integ = dict(_HARDENED, filevault_active=0, firewall_global_state=0)
        r = compute_risk_score(integ, 0, 0, 0, 0)
        assert r["score"] == 70 and r["grade"] == "C"  # -15 -15
        labels = {d["label"] for d in r["drivers"]}
        assert any("FileVault" in lbl for lbl in labels)
        assert any("Firewall off" in lbl for lbl in labels)

    def test_finding_penalties_are_capped(self):
        from avai.host_monitor import compute_risk_score

        # 5 malicious → capped at 40; 5 suspicious → capped at 24 → 100-64=36
        r = compute_risk_score(None, 5, 5, 0, 0)
        assert r["score"] == 36 and r["grade"] == "F"

    def test_none_integrity_fields_cost_nothing(self):
        from avai.host_monitor import compute_risk_score

        r = compute_risk_score(None, 0, 0, 0, 0)
        assert r["score"] == 100 and r["grade"] == "A"

    def test_privilege_penalties(self):
        from avai.host_monitor import compute_risk_score

        r = compute_risk_score(_HARDENED, 0, 0, 1, 1)  # -10 nopasswd -15 uid0
        assert r["score"] == 75 and r["grade"] == "C"


class TestRiskExplanation:
    def test_initial_score(self):
        assert "Initial" in Runner._risk_explanation({"score": 90, "drivers": []}, None)

    def test_resolved_driver_raises_score(self):
        class _Prev:
            score = 80
            drivers_json = '[{"label":"Firewall off","points":15}]'

        e = Runner._risk_explanation({"score": 95, "drivers": []}, _Prev)
        assert "up 15" in e and "Resolved" in e and "Firewall off" in e

    def test_new_driver_lowers_score(self):
        class _Prev:
            score = 100
            drivers_json = "[]"

        e = Runner._risk_explanation(
            {"score": 85, "drivers": [{"label": "Firewall off", "points": 15}]}, _Prev
        )
        assert "down 15" in e and "New" in e and "Firewall off" in e


class TestRiskScoreSink:
    def test_privilege_and_integrity_queries(self, sink):
        from avai.host_monitor import PrivilegeConfigRow, SystemIntegrityRow

        _w(sink, SystemIntegrityRow, run_id="r1", collected_at=_TS[0],
           filevault_active=0, firewall_global_state=1)
        _w(sink, PrivilegeConfigRow, run_id="r1", collected_at=_TS[0],
           kind="sudoers", subject="dev", detail="ALL=(ALL) NOPASSWD: ALL")
        _w(sink, PrivilegeConfigRow, run_id="r1", collected_at=_TS[0],
           kind="account", subject="backdoor", detail="uid=0")
        _w(sink, PrivilegeConfigRow, run_id="r1", collected_at=_TS[0],
           kind="account", subject="root", detail="uid=0")

        integ = sink.system_integrity_row("r1")
        assert integ["filevault_active"] == 0 and integ["firewall_global_state"] == 1
        nopasswd, uid0 = sink.privilege_risk_counts("r1")
        assert nopasswd == 1 and uid0 == 1  # 'root' excluded

    def test_write_and_latest_risk(self, sink):
        sink.write_risk_score({
            "created_at": _TS[0], "run_id": "r1", "score": 72, "grade": "C",
            "prev_score": None, "drivers_json": "[]", "explanation": "init",
        })
        row = sink.latest_risk_row()
        assert row.score == 72 and row.grade == "C"


# ---------------------------------------------------------------------------
# LLM cost estimation + attribution
# ---------------------------------------------------------------------------


class TestEstimateCost:
    def test_haiku_tier_pricing(self):
        from avai.host_monitor import estimate_cost

        # 1M input @ $1, 1M output @ $5
        assert estimate_cost("claude-haiku-4-5", 1_000_000, 0) == pytest.approx(1.0)
        assert estimate_cost("claude-haiku-4-5", 0, 1_000_000) == pytest.approx(5.0)

    def test_tier_matched_by_substring(self):
        from avai.host_monitor import estimate_cost

        assert estimate_cost("claude-opus-4-8", 1_000_000, 0) == pytest.approx(15.0)
        assert estimate_cost("anthropic/claude-sonnet-4-6", 0, 1_000_000) == pytest.approx(15.0)

    def test_unknown_model_uses_default_tier(self):
        from avai.host_monitor import estimate_cost

        assert estimate_cost("mystery-model", 1_000_000, 0) == pytest.approx(1.0)


class TestJudgmentCostPersistence:
    def test_cost_usd_persisted(self, sink):
        from avai.host_monitor import Judgement, Judgment, ThreatCategory, Verdict

        j = Judgment(
            content_hash="hc", collector="processes", verdict=Verdict.MALICIOUS,
            category=ThreatCategory.PERSISTENCE, confidence=0.9, reasoning="r",
            remediation="", model="m", created_at="2026-01-01T00:00:00Z",
            cost_usd=0.0012,
        )
        sink.write_judgments([j])
        with Session(sink.engine) as s:
            row = s.get(Judgement, ("hc", "processes"))
        assert row.cost_usd == pytest.approx(0.0012)
