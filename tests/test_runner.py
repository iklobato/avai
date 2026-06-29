"""Tests for the Runner — specifically its enrichment-phase wiring
(``_enrich_entries``) and the cycle's overall sequencing.

The full ``Runner.run_once`` pulls in the collector factory which
needs platform-specific binaries, so we don't drive it end-to-end
here. Instead we build a Runner with hand-rolled fakes and exercise
just the methods that mediate enrichment + judging.
"""

from __future__ import annotations

import json

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
    FileScanRow,
    NullJudge,
    ProcessRow,
    Runner,
    Sink,
)
from avai.host_monitor.runtime import Clock, Digest, FrozenClock


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
                "collected_at": Clock().now_iso(),
                "content_hash": Digest.of_row(
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
        h = Digest.of_row({"raddr": "8.8.8.8:53"}, collector.judge_fields)
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


class TestProgressHeartbeat:
    """run_once must keep the control row's last_seen_at fresh *during* a
    scan, not only between scans. Regression: a first cycle that ran longer
    than the dashboard's liveness window (minutes-to-hours of serial
    enrichment over many indicators) left last_seen_at frozen, so the
    dashboard reported the live, busy monitor as 'monitor offline'."""

    def test_touch_heartbeat_refreshes_only_last_seen_at(self, sink, monkeypatch):
        import avai.host_monitor.sink as sink_mod

        sink.ensure_control_row(interval=300, judge_enabled=False, enrich_enabled=False)
        start = "2026-06-23T23:07:51+00:00"
        monkeypatch.setattr(sink_mod, "Clock", lambda: FrozenClock(start))
        sink.write_heartbeat(pid=42, status="scanning", current_interval=300)
        before = sink.read_control()

        later = "2026-06-23T23:20:00+00:00"
        monkeypatch.setattr(sink_mod, "Clock", lambda: FrozenClock(later))
        sink.touch_heartbeat()
        after = sink.read_control()

        assert after["last_seen_at"] == later  # liveness refreshed
        # Status/interval/applied_at belong to write_heartbeat — a mid-scan
        # touch must not claim a status change or a control-application.
        assert after["status"] == before["status"]
        assert after["applied_at"] == start
        assert after["current_interval"] == before["current_interval"]
        assert after["pid"] == before["pid"]

    def test_run_once_refreshes_liveness_at_each_collector(self, sink, monkeypatch):
        import avai.host_monitor.runner as runner_mod

        # Zero the throttle so each collector boundary writes; the test scan
        # is far shorter than the real interval.
        monkeypatch.setattr(runner_mod, "MONITOR_PROGRESS_HEARTBEAT_S", 0)
        sink.ensure_control_row(interval=300, judge_enabled=False, enrich_enabled=False)

        beats = {"n": 0}
        real_touch = sink.touch_heartbeat

        def counting_touch():
            beats["n"] += 1
            real_touch()

        monkeypatch.setattr(sink, "touch_heartbeat", counting_touch)

        _CountingCollector.calls = []
        c1 = _CountingCollector("a")
        c2 = _CountingCollector("b")
        runner = Runner(sink, [c1, c2], [], NullJudge(), 5)
        runner.run_once()

        # One liveness touch per collector boundary: the monitor proves it's
        # alive as the scan advances, not only when it finishes.
        assert beats["n"] >= 2


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
    h = Digest.of_row({"name": name}, ("name",))
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

    def test_intermittent_flagged_for_flapping_artifact(self, sink):
        # 5 runs. "steady" appears every run; "flap" only in runs 0 and 2
        # (present in fewer runs than its window → flapping); "fresh" only in
        # the last run (window too short to call intermittent).
        for ts in _TS[:5]:
            _add_run(sink, ts)
        for ts in _TS[:5]:
            _add_proc(sink, ts, ts, "steady")
        for ts in (_TS[0], _TS[2]):
            _add_proc(sink, ts, ts, "flap")
        _add_proc(sink, _TS[4], _TS[4], "fresh")

        runner = Runner(sink, [], [], NullJudge(), 5, baseline_min_runs=2)
        bl = runner._host_baseline()
        unjudged = [
            {"content_hash": Digest.of_row({"name": n}, ("name",)), "name": n}
            for n in ("steady", "flap", "fresh")
        ]
        runner._annotate_baseline(_ProcStub(), unjudged, bl)
        steady, flap, fresh = unjudged
        assert flap["baseline"]["intermittent"] is True
        assert steady["baseline"]["intermittent"] is False  # present every run
        assert fresh["baseline"]["intermittent"] is False  # window too short


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

        h = Digest.of_row({"name": "evil"}, ("name",))
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

    def test_launch_items_correlate_via_program_to_process(self, sink):
        # A launch item has no PID; its program is resolved to the live
        # process running it, then that process's behaviour is attached.
        from avai.host_monitor import LaunchItemRow, NetworkFlowRow, ProcessRow

        self._setup_two_runs(sink)
        _w(
            sink,
            ProcessRow,
            pid=42,
            name="foo",
            exe="/usr/local/bin/foo",
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
            packets=99,
            run_id=_TS[0],
            collected_at=_TS[0],
        )

        class _LaunchStub:
            name = "launch_items"
            model = LaunchItemRow
            judge_fields = ("label", "program")
            judge_hints = ""

        h = "launch-hash"
        rows = [{"content_hash": h, "program": "/usr/local/bin/foo", "label": "com.x"}]
        unjudged = [{"content_hash": h, "label": "com.x"}]
        runner = Runner(sink, [], [], NullJudge(), 5)
        runner._attach_correlation(_LaunchStub(), unjudged, rows, _TS[1])
        rel = unjudged[0]["related"]
        assert rel["outbound_flows"][0]["dst"] == "9.9.9.9:443"
        assert rel["outbound_flows"][0]["packets"] == 99

    def test_launch_item_without_running_program_gets_no_related(self, sink):
        from avai.host_monitor import LaunchItemRow

        self._setup_two_runs(sink)

        class _LaunchStub:
            name = "launch_items"
            model = LaunchItemRow
            judge_fields = ("label", "program")
            judge_hints = ""

        rows = [{"content_hash": "h", "program": "/never/running", "label": "com.y"}]
        unjudged = [{"content_hash": "h", "label": "com.y"}]
        runner = Runner(sink, [], [], NullJudge(), 5)
        runner._attach_correlation(_LaunchStub(), unjudged, rows, _TS[1])
        assert "related" not in unjudged[0]

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
        h = Digest.of_row({"name": "quiet"}, ("name",))
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

        h = Digest.of_row({"name": "evil"}, ("name",))
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

    def test_findings_are_capped_keeping_most_severe(self):
        # Regression: an unbounded findings list could blow the LLM context
        # window and fail the digest every cycle. narrate() caps to
        # MAX_FINDINGS, keeping the most severe/confident.
        from avai.host_monitor import DEFAULT_PROMPTS_PATH, IncidentNarrator, Prompts

        class _FakeClient:
            def __init__(self):
                self.calls = []

            def complete_structured(self, **kw):
                self.calls.append(kw)
                return {
                    "headline": "h",
                    "severity": "high",
                    "summary": "s",
                    "timeline": [],
                    "actions": [],
                }

        client = _FakeClient()
        nar = IncidentNarrator(
            prompts=Prompts.load(DEFAULT_PROMPTS_PATH), client=client
        )
        cap = IncidentNarrator.MAX_FINDINGS
        findings = [
            {"content_hash": "keep", "verdict": "malicious", "confidence": 0.99}
        ]
        findings += [
            {"content_hash": f"f{i}", "verdict": "suspicious", "confidence": 0.1}
            for i in range(cap + 20)
        ]
        nar.narrate(findings)
        user = client.calls[0]["user"]
        assert user.count('"content_hash"') == cap  # trimmed to the cap
        assert '"keep"' in user  # the malicious finding survived the trim

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

        _w(
            sink,
            SystemIntegrityRow,
            run_id="r1",
            collected_at=_TS[0],
            filevault_active=0,
            firewall_global_state=1,
        )
        _w(
            sink,
            PrivilegeConfigRow,
            run_id="r1",
            collected_at=_TS[0],
            kind="sudoers",
            subject="dev",
            detail="ALL=(ALL) NOPASSWD: ALL",
        )
        _w(
            sink,
            PrivilegeConfigRow,
            run_id="r1",
            collected_at=_TS[0],
            kind="account",
            subject="backdoor",
            detail="uid=0",
        )
        _w(
            sink,
            PrivilegeConfigRow,
            run_id="r1",
            collected_at=_TS[0],
            kind="account",
            subject="root",
            detail="uid=0",
        )

        integ = sink.system_integrity_row("r1")
        assert integ["filevault_active"] == 0 and integ["firewall_global_state"] == 1
        nopasswd, uid0 = sink.privilege_risk_counts("r1")
        assert nopasswd == 1 and uid0 == 1  # 'root' excluded

    def test_write_and_latest_risk(self, sink):
        sink.write_risk_score(
            {
                "created_at": _TS[0],
                "run_id": "r1",
                "score": 72,
                "grade": "C",
                "prev_score": None,
                "drivers_json": "[]",
                "explanation": "init",
            }
        )
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
        assert estimate_cost(
            "anthropic/claude-sonnet-4-6", 0, 1_000_000
        ) == pytest.approx(15.0)

    def test_unknown_model_uses_default_tier(self):
        from avai.host_monitor import estimate_cost

        assert estimate_cost("mystery-model", 1_000_000, 0) == pytest.approx(1.0)


class TestJudgmentCostPersistence:
    def test_cost_usd_persisted(self, sink):
        from avai.host_monitor import Judgement, Judgment, ThreatCategory, Verdict

        j = Judgment(
            content_hash="hc",
            collector="processes",
            verdict=Verdict.MALICIOUS,
            category=ThreatCategory.PERSISTENCE,
            confidence=0.9,
            reasoning="r",
            remediation="",
            model="m",
            created_at="2026-01-01T00:00:00Z",
            cost_usd=0.0012,
        )
        sink.write_judgments([j])
        with Session(sink.engine) as s:
            row = s.get(Judgement, ("hc", "processes"))
        assert row.cost_usd == pytest.approx(0.0012)


# ---------------------------------------------------------------------------
# Cooperative control plane
# ---------------------------------------------------------------------------


def _set_control(sink, **vals):
    """Write fields onto the single control row (creating it if needed)."""
    from sqlalchemy import update

    from avai.host_monitor import ControlState

    sink.ensure_control_row(interval=300, judge_enabled=True, enrich_enabled=True)
    with Session(sink.engine) as s:
        s.execute(update(ControlState).where(ControlState.id == 1).values(**vals))
        s.commit()


class TestControlSink:
    def test_round_trip_and_acks(self, sink):
        sink.ensure_control_row(interval=120, judge_enabled=True, enrich_enabled=False)
        c = sink.read_control()
        assert c["interval_override"] == 120
        assert c["judge_enabled"] == 1 and c["enrich_enabled"] == 0
        assert c["paused"] == 0
        sink.write_heartbeat(pid=4321, status="running", current_interval=120)
        sink.ack_scan_now(7)
        sink.ack_command(3, "ok")
        c = sink.read_control()
        assert c["pid"] == 4321 and c["status"] == "running"
        assert c["scan_now_applied"] == 7
        assert c["command_applied"] == 3 and c["command_result"] == "ok"

    def test_ensure_is_idempotent(self, sink):
        sink.ensure_control_row(interval=100, judge_enabled=True, enrich_enabled=True)
        _set_control(sink, paused=1)
        sink.ensure_control_row(interval=999, judge_enabled=False, enrich_enabled=False)
        c = sink.read_control()
        assert c["paused"] == 1 and c["interval_override"] == 100  # not clobbered


class TestControlSettingsGating:
    def test_disabled_collector_is_skipped(self, sink):
        _CountingCollector.calls = []
        a = _CountingCollector("a")
        b = _CountingCollector("b")
        _set_control(sink, disabled_collectors="a")
        runner = Runner(sink, [a, b], [], NullJudge(), 5)
        runner.run_once()
        assert _CountingCollector.calls == ["b"]  # "a" skipped

    def test_judge_and_enrich_toggles(self, sink):
        runner = Runner(sink, [], [], NullJudge(), 5, enrichment_chain=None)
        _set_control(sink, judge_enabled=0, enrich_enabled=0)
        runner._refresh_control()
        assert runner._judge_on() is False and runner._enrich_on() is False
        _set_control(sink, judge_enabled=1, enrich_enabled=1)
        runner._refresh_control()
        assert runner._judge_on() is True and runner._enrich_on() is True

    def test_settings_default_to_constructor_state_when_unset(self, sink):
        runner = Runner(sink, [], [], NullJudge(), 5, enrichment_chain=None)
        _set_control(sink, judge_enabled=None, enrich_enabled=None)
        runner._refresh_control()
        # None => fall back to what the monitor was built with.
        assert runner._judge_on() is False  # NullJudge
        assert runner._enrich_on() is False  # no chain


class TestControlCommands:
    def test_rejudge_clears_judgements_and_acks(self, sink):
        from avai.host_monitor import Judgement

        with Session(sink.engine) as s:
            s.add(
                Judgement(
                    content_hash="h1",
                    collector="processes",
                    verdict="benign",
                    model="m",
                    created_at=Clock().now_iso(),
                )
            )
            s.commit()
        _set_control(sink, command="rejudge", command_nonce=1, command_applied=0)
        runner = Runner(sink, [], [], NullJudge(), 5)
        runner._run_pending_command(sink.read_control())
        with Session(sink.engine) as s:
            assert s.query(Judgement).count() == 0
        c = sink.read_control()
        assert c["command_applied"] == 1
        assert "judgement" in c["command_result"]

    def test_reset_baseline_drops_runs(self, sink):
        _add_run(sink, _TS[0])
        _add_run(sink, _TS[1])
        _set_control(sink, command="reset_baseline", command_nonce=1, command_applied=0)
        runner = Runner(sink, [], [], NullJudge(), 5)
        runner._run_pending_command(sink.read_control())
        assert sink.completed_run_count() == 0
        assert sink.read_control()["command_applied"] == 1

    def test_already_applied_command_is_skipped(self, sink):
        _set_control(sink, command="clear", command_nonce=2, command_applied=2)
        runner = Runner(sink, [], [], NullJudge(), 5)
        # nonce == applied → no-op (no exception, result unchanged)
        runner._run_pending_command(sink.read_control())
        assert sink.read_control()["command_applied"] == 2


class TestControlLoop:
    """Drive a single iteration of run_forever by having the stubbed
    run_once / heartbeat request shutdown, so the loop exits deterministically."""

    def test_runs_a_cycle_when_not_paused(self, sink):
        _set_control(sink, paused=0)
        runner = Runner(sink, [], [], NullJudge(), 5)
        calls = []

        def fake_run_once():
            calls.append(1)
            runner.request_shutdown()
            return ("rid", 0, 0)

        runner.run_once = fake_run_once
        runner.run_forever(300)
        assert calls == [1]

    def test_paused_skips_the_cycle(self, sink):
        _set_control(sink, paused=1)
        runner = Runner(sink, [], [], NullJudge(), 5)
        calls = []
        runner.run_once = lambda: calls.append(1) or ("rid", 0, 0)
        orig = runner._heartbeat

        def fake_hb(status, interval):  # stop the loop after one tick
            orig(status, interval)
            runner.request_shutdown()

        runner._heartbeat = fake_hb
        runner.run_forever(300)
        assert calls == []  # paused → never scanned
        assert sink.read_control()["status"] == "paused"

    def test_scan_now_overrides_pause_and_acks(self, sink):
        _set_control(sink, paused=1, scan_now_nonce=1, scan_now_applied=0)
        runner = Runner(sink, [], [], NullJudge(), 5)
        calls = []

        def fake_run_once():
            calls.append(1)
            runner.request_shutdown()
            return ("rid", 0, 0)

        runner.run_once = fake_run_once
        runner.run_forever(300)
        assert calls == [1]  # scan-now forced a cycle despite pause
        assert sink.read_control()["scan_now_applied"] == 1


class _FileScanStub:
    name = "file_scan"
    model = FileScanRow
    judge_enabled = True
    judge_fields = ("path", "sha256", "rule", "namespace", "tags_json")
    judge_hints = ""


class TestAttachYaraContext:
    """The Runner surfaces a YARA hit's rule meta + matched bytes to the
    judge without touching the content_hash (they aren't judge_fields)."""

    def _runner(self, sink):
        return Runner(sink, [], [], _RecordingJudge(), 5)

    def test_attaches_meta_and_strings_from_row(self, sink):
        runner = self._runner(sink)
        h = "hash-1"
        rows = [
            {
                "content_hash": h,
                "meta_json": json.dumps(
                    {"author": "Jane", "description": "APT42 implant loader"}
                ),
                "strings_json": json.dumps(
                    [{"id": "$c2", "offset": 16, "text": "http://evil.example/x"}]
                ),
            }
        ]
        unjudged = [{"content_hash": h, "rule": "apt42_loader"}]
        runner._attach_yara_context(_FileScanStub(), unjudged, rows)
        assert unjudged[0]["rule_meta"]["description"] == "APT42 implant loader"
        assert unjudged[0]["matched_strings"][0]["text"] == "http://evil.example/x"

    def test_other_collectors_are_untouched(self, sink):
        runner = self._runner(sink)
        unjudged = [{"content_hash": "h", "name": "x"}]
        # _StubCollector.name is "processes" — not the file_scan collector.
        runner._attach_yara_context(
            _StubCollector(), unjudged, [{"content_hash": "h", "meta_json": "{}"}]
        )
        assert "rule_meta" not in unjudged[0]
        assert "matched_strings" not in unjudged[0]

    def test_missing_and_malformed_json_is_tolerated(self, sink):
        runner = self._runner(sink)
        h = "hash-2"
        # No meta, malformed strings — neither key should be attached, no raise.
        rows = [{"content_hash": h, "strings_json": "{not json"}]
        unjudged = [{"content_hash": h, "rule": "r"}]
        runner._attach_yara_context(_FileScanStub(), unjudged, rows)
        assert "rule_meta" not in unjudged[0]
        assert "matched_strings" not in unjudged[0]

    def test_entry_without_matching_row_is_skipped(self, sink):
        runner = self._runner(sink)
        unjudged = [{"content_hash": "absent", "rule": "r"}]
        runner._attach_yara_context(
            _FileScanStub(), unjudged, [{"content_hash": "other", "meta_json": "{}"}]
        )
        assert "rule_meta" not in unjudged[0]


# ---------------------------------------------------------------------------
# YARA ruleset-coverage assessment
# ---------------------------------------------------------------------------


class _FakeAssessor:
    model = "fake-cov-model"

    def __init__(self, result=None):
        self.calls = []
        self._result = result or {
            "posture": "thin",
            "headline": "Windows-centric ruleset on a Mac",
            "summary": "Few macOS rules for this host's surface.",
            "gaps": [{"area": "macOS persistence", "detail": "no LaunchAgent rules"}],
            "recommendations": [
                {"action": "fetch signature-base", "detail": "adds macOS coverage"}
            ],
        }

    def assess(self, ruleset, host):
        self.calls.append((ruleset, host))
        return self._result


def _seed_yara_status(sink, rules_loaded=10, sources=None, by_category=None):
    sink.write_yara_status(
        {
            "rules_loaded": rules_loaded,
            "files_loaded": rules_loaded,
            "files_skipped": 0,
            "rules_dir": "/rules",
            "sources": sources or {"bundled": rules_loaded},
            "skip_reasons": {},
            "by_category": by_category or {"gen": rules_loaded},
        }
    )


def _latest_coverage_row(sink):
    from sqlalchemy import desc, select

    from avai.host_monitor import YaraCoverageRow

    with Session(sink.engine) as s:
        return (
            s.execute(
                select(YaraCoverageRow).order_by(desc(YaraCoverageRow.created_at))
            )
            .scalars()
            .first()
        )


class TestGenerateCoverage:
    def _runner(self, sink, assessor):
        return Runner(sink, [], [], NullJudge(), 5, coverage=assessor)

    def test_no_ruleset_no_assessment(self, sink):
        a = _FakeAssessor()
        self._runner(sink, a)._generate_coverage("run-1", _TS[1])
        assert a.calls == []
        assert sink.latest_yara_coverage_fingerprint() is None

    def test_zero_rules_no_assessment(self, sink):
        _seed_yara_status(sink, rules_loaded=0)
        a = _FakeAssessor()
        self._runner(sink, a)._generate_coverage("run-1", _TS[1])
        assert a.calls == []

    def test_assessment_generated_and_stored(self, sink):
        _seed_yara_status(sink)
        a = _FakeAssessor()
        self._runner(sink, a)._generate_coverage("run-1", _TS[1])
        assert len(a.calls) == 1
        # The host profile passed carries the platform + inventory counts.
        _ruleset, host = a.calls[0]
        assert "platform" in host and "processes" in host
        row = _latest_coverage_row(sink)
        assert row.posture == "thin"
        assert row.headline.startswith("Windows-centric")
        assert json.loads(row.gaps_json)[0]["area"] == "macOS persistence"
        assert row.ruleset_fingerprint  # stored for dedup

    def test_unchanged_ruleset_not_regenerated(self, sink):
        _seed_yara_status(sink)
        a = _FakeAssessor()
        r = self._runner(sink, a)
        r._generate_coverage("run-1", _TS[1])
        r._generate_coverage("run-2", _TS[1])
        assert len(a.calls) == 1  # same ruleset fingerprint → skipped

    def test_changed_ruleset_regenerates(self, sink):
        _seed_yara_status(sink, rules_loaded=10)
        a = _FakeAssessor()
        r = self._runner(sink, a)
        r._generate_coverage("run-1", _TS[1])
        _seed_yara_status(sink, rules_loaded=99)  # ruleset changed
        r._generate_coverage("run-2", _TS[1])
        assert len(a.calls) == 2


class TestYaraCoverageAssessor:
    def _assessor(self, payload):
        from avai.host_monitor import DEFAULT_PROMPTS_PATH, Prompts
        from avai.host_monitor.coverage import YaraCoverageAssessor

        class _FakeClient:
            def __init__(self):
                self.calls = []

            def complete_structured(self, **kw):
                self.calls.append(kw)
                return payload

        return YaraCoverageAssessor(
            prompts=Prompts.load(DEFAULT_PROMPTS_PATH), client=_FakeClient()
        )

    _RULESET = {"rules_loaded": 5, "sources": {"bundled": 5}, "by_category": {"gen": 5}}

    def test_prompt_section_loads(self):
        from avai.host_monitor import DEFAULT_PROMPTS_PATH, Prompts

        p = Prompts.load(DEFAULT_PROMPTS_PATH)
        assert p.coverage_system and "$ruleset" in p.coverage_user_template

    def test_empty_ruleset_returns_none_without_calling_llm(self):
        a = self._assessor({"posture": "thin", "headline": "h", "summary": "s"})
        assert a.assess({}, {"platform": "Darwin"}) is None
        assert a.assess({"rules_loaded": 0}, {}) is None

    def test_bad_posture_falls_back_to_partial(self):
        a = self._assessor(
            {
                "posture": "fortified",
                "headline": "h",
                "summary": "s",
                "gaps": [],
                "recommendations": [],
            }
        )
        out = a.assess(self._RULESET, {"platform": "Darwin"})
        assert out["posture"] == "partial"

    def test_missing_headline_returns_none(self):
        a = self._assessor({"posture": "thin", "summary": "s", "gaps": []})
        assert a.assess(self._RULESET, {}) is None

    def test_gaps_and_recommendations_normalised(self):
        a = self._assessor(
            {
                "posture": "thin",
                "headline": "h",
                "summary": "s",
                "gaps": [
                    {"area": "macOS", "detail": "d"},
                    {"detail": "no area → dropped"},
                ],
                "recommendations": [
                    {"action": "fetch pack", "detail": "d"},
                    {"detail": "no action → dropped"},
                ],
            }
        )
        out = a.assess(self._RULESET, {"platform": "Darwin"})
        assert len(out["gaps"]) == 1 and out["gaps"][0]["area"] == "macOS"
        assert len(out["recommendations"]) == 1
        assert out["recommendations"][0]["action"] == "fetch pack"


# ---------------------------------------------------------------------------
# Malicious-verdict verifier (adversarial second pass)
# ---------------------------------------------------------------------------


def _mk_judgment(h, verdict, collector="processes"):
    from avai.host_monitor import Judgment, ThreatCategory

    return Judgment(
        content_hash=h,
        collector=collector,
        verdict=verdict,
        category=ThreatCategory.PERSISTENCE,
        confidence=0.9,
        reasoning="original reason",
        remediation="",
        model="m",
        created_at="2026-01-01T00:00:00Z",
    )


class _FakeVerifier:
    def __init__(self, refuted):
        self._refuted = refuted
        self.calls = []

    def verify(self, finding):
        self.calls.append(finding)
        return {"refuted": self._refuted, "reasoning": "skeptic says so"}


class TestVerifyJudgments:
    def _runner(self, sink, verifier=None):
        return Runner(sink, [], [], NullJudge(), 5, verifier=verifier)

    def test_refuted_malicious_downgraded_to_suspicious(self, sink):
        from avai.host_monitor import Verdict

        v = _FakeVerifier(refuted=True)
        j = _mk_judgment("h1", Verdict.MALICIOUS)
        out = self._runner(sink, v)._verify_judgments(
            "processes", [j], [{"content_hash": "h1", "name": "x"}]
        )
        assert out[0].verdict == Verdict.SUSPICIOUS
        assert "downgraded" in out[0].reasoning
        assert "original reason" in out[0].reasoning  # original preserved
        assert len(v.calls) == 1

    def test_unrefuted_malicious_is_kept(self, sink):
        from avai.host_monitor import Verdict

        v = _FakeVerifier(refuted=False)
        j = _mk_judgment("h1", Verdict.MALICIOUS)
        out = self._runner(sink, v)._verify_judgments(
            "processes", [j], [{"content_hash": "h1"}]
        )
        assert out[0].verdict == Verdict.MALICIOUS
        assert len(v.calls) == 1

    def test_non_malicious_is_not_verified(self, sink):
        from avai.host_monitor import Verdict

        v = _FakeVerifier(refuted=True)
        j = _mk_judgment("h1", Verdict.SUSPICIOUS)
        out = self._runner(sink, v)._verify_judgments("processes", [j], [])
        assert out[0].verdict == Verdict.SUSPICIOUS
        assert v.calls == []  # skeptic only runs on malicious

    def test_no_verifier_is_noop(self, sink):
        from avai.host_monitor import Verdict

        j = _mk_judgment("h1", Verdict.MALICIOUS)
        out = self._runner(sink)._verify_judgments("processes", [j], [])
        assert out[0].verdict == Verdict.MALICIOUS


class TestMaliciousVerdictVerifier:
    def _verifier(self, payload):
        from avai.host_monitor import DEFAULT_PROMPTS_PATH, Prompts
        from avai.host_monitor.verifier import MaliciousVerdictVerifier

        class _FakeClient:
            def __init__(self):
                self.calls = []

            def complete_structured(self, **kw):
                self.calls.append(kw)
                return payload

        return MaliciousVerdictVerifier(
            prompts=Prompts.load(DEFAULT_PROMPTS_PATH), client=_FakeClient()
        )

    def test_refuted_true_parsed(self):
        out = self._verifier(
            {"refuted": True, "reasoning": "signed Apple binary"}
        ).verify({"artifact": "x"})
        assert out["refuted"] is True
        assert "signed" in out["reasoning"]

    def test_missing_fields_default_to_not_refuted(self):
        # Absent/garbled output must not silently downgrade a verdict.
        out = self._verifier({}).verify({"artifact": "x"})
        assert out["refuted"] is False


# ---------------------------------------------------------------------------
# Unknown-finding investigator (deep re-judge)
# ---------------------------------------------------------------------------


class _FakeInvestigator:
    def __init__(self, verdict, category=None):
        from avai.host_monitor import ThreatCategory

        self._verdict = verdict
        self._category = category or ThreatCategory.COMMAND_AND_CONTROL
        self.calls = []

    def investigate(self, collector, finding):
        self.calls.append((collector, finding))
        return {
            "verdict": self._verdict,
            "category": self._category,
            "confidence": 0.8,
            "reasoning": "deep look decided it",
            "remediation": "do x",
        }


class TestInvestigateUnknowns:
    def _runner(self, sink, investigator=None):
        return Runner(sink, [], [], NullJudge(), 5, investigator=investigator)

    def test_unknown_resolved_replaces_verdict(self, sink):
        from avai.host_monitor import Verdict

        inv = _FakeInvestigator(Verdict.MALICIOUS)
        j = _mk_judgment("h1", Verdict.UNKNOWN)
        out = self._runner(sink, inv)._investigate_unknowns(
            _ProcStub(), [j], [{"content_hash": "h1", "name": "evil"}], []
        )
        assert out[0].verdict == Verdict.MALICIOUS
        assert out[0].reasoning.startswith("[investigated]")
        assert len(inv.calls) == 1

    def test_unknown_kept_when_still_unknown(self, sink):
        from avai.host_monitor import Verdict

        inv = _FakeInvestigator(Verdict.UNKNOWN)
        j = _mk_judgment("h1", Verdict.UNKNOWN)
        out = self._runner(sink, inv)._investigate_unknowns(
            _ProcStub(), [j], [{"content_hash": "h1"}], []
        )
        assert out[0].verdict == Verdict.UNKNOWN
        assert len(inv.calls) == 1  # investigated, but couldn't commit

    def test_non_unknown_not_investigated(self, sink):
        from avai.host_monitor import Verdict

        inv = _FakeInvestigator(Verdict.MALICIOUS)
        j = _mk_judgment("h1", Verdict.SUSPICIOUS)
        out = self._runner(sink, inv)._investigate_unknowns(_ProcStub(), [j], [], [])
        assert out[0].verdict == Verdict.SUSPICIOUS
        assert inv.calls == []

    def test_no_investigator_is_noop(self, sink):
        from avai.host_monitor import Verdict

        j = _mk_judgment("h1", Verdict.UNKNOWN)
        out = self._runner(sink)._investigate_unknowns(_ProcStub(), [j], [], [])
        assert out[0].verdict == Verdict.UNKNOWN

    def test_finding_carries_full_history_behaviour(self, sink):
        from avai.host_monitor import NetworkFlowRow, Verdict

        # A flow for pid 42 in history (no run-time bound applies under
        # investigation), resolved via the process row passed in.
        _w(
            sink,
            NetworkFlowRow,
            pid=42,
            dst_ip="9.9.9.9",
            dst_port=443,
            service="https",
            packets=5,
            run_id="r0",
            collected_at=_TS[0],
        )
        inv = _FakeInvestigator(Verdict.MALICIOUS)
        j = _mk_judgment("h1", Verdict.UNKNOWN)
        rows = [{"content_hash": "h1", "pid": 42, "name": "evil"}]
        self._runner(sink, inv)._investigate_unknowns(
            _ProcStub(), [j], [{"content_hash": "h1", "name": "evil"}], rows
        )
        _collector, finding = inv.calls[0]
        assert finding["related_full"]["outbound_flows"][0]["dst"] == "9.9.9.9:443"


class TestUnknownFindingInvestigator:
    def _inv(self, payload):
        from avai.host_monitor import DEFAULT_PROMPTS_PATH, Prompts
        from avai.host_monitor.investigator import UnknownFindingInvestigator

        class _FakeClient:
            def complete_structured(self, **kw):
                return payload

        return UnknownFindingInvestigator(
            prompts=Prompts.load(DEFAULT_PROMPTS_PATH), client=_FakeClient()
        )

    def test_parses_and_clamps(self):
        from avai.host_monitor import ThreatCategory, Verdict

        out = self._inv(
            {
                "verdict": "malicious",
                "category": "command_and_control",
                "confidence": 1.5,
                "reasoning": "r",
                "remediation": "x",
            }
        ).investigate("processes", {"a": 1})
        assert out["verdict"] == Verdict.MALICIOUS
        assert out["category"] == ThreatCategory.COMMAND_AND_CONTROL
        assert out["confidence"] == 1.0  # clamped to [0,1]

    def test_bad_verdict_coerces_to_unknown(self):
        from avai.host_monitor import Verdict

        out = self._inv(
            {
                "verdict": "scary",
                "category": "nope",
                "confidence": 0.5,
                "reasoning": "r",
                "remediation": "",
            }
        ).investigate("processes", {})
        assert out["verdict"] == Verdict.UNKNOWN


# ---------------------------------------------------------------------------
# Operator feedback loop
# ---------------------------------------------------------------------------


def _add_feedback(sink, h, collector, label, note=None, artifact=None, applied=0):
    from avai.host_monitor import FeedbackRow

    with Session(sink.engine) as s:
        s.add(
            FeedbackRow(
                content_hash=h,
                collector=collector,
                label=label,
                note=note,
                artifact=artifact,
                created_at="2026-01-01T00:00:00Z",
                applied=applied,
            )
        )
        s.commit()


class TestFeedback:
    def test_apply_feedback_flips_to_benign_and_marks_applied(self, sink):
        from avai.host_monitor import Judgement, Verdict

        _add_judgement(sink, "h1", "malicious", last_seen=_TS[1])
        _add_feedback(sink, "h1", "processes", "false_positive", note="known dev tool")
        assert sink.apply_feedback() == 1
        with Session(sink.engine) as s:
            row = s.get(Judgement, ("h1", "processes"))
        assert row.verdict == str(Verdict.BENIGN)
        assert "operator" in row.reasoning and "known dev tool" in row.reasoning
        assert sink.apply_feedback() == 0  # already applied → not reprocessed

    def test_apply_feedback_confirmed_to_malicious(self, sink):
        from avai.host_monitor import Judgement, Verdict

        _add_judgement(sink, "h2", "suspicious", last_seen=_TS[1])
        _add_feedback(sink, "h2", "processes", "confirmed")
        sink.apply_feedback()
        with Session(sink.engine) as s:
            row = s.get(Judgement, ("h2", "processes"))
        assert row.verdict == str(Verdict.MALICIOUS)

    def test_feedback_examples_scoped_to_collector(self, sink):
        _add_feedback(sink, "h1", "processes", "false_positive", artifact="curl")
        ex = sink.feedback_examples("processes")
        assert ex and ex[0]["artifact"] == "curl"
        assert ex[0]["label"] == "false_positive"
        assert sink.feedback_examples("dns_queries") == []

    def test_judge_hints_appends_ground_truth_block(self, sink):
        _add_feedback(
            sink, "h1", "processes", "false_positive", artifact="curl", note="dev tool"
        )
        runner = Runner(sink, [], [], NullJudge(), 5)
        hints = runner._judge_hints("processes", "BASE HINTS")
        assert hints.startswith("BASE HINTS")
        assert "curl" in hints and "FALSE POSITIVE" in hints and "dev tool" in hints

    def test_judge_hints_unchanged_without_feedback(self, sink):
        runner = Runner(sink, [], [], NullJudge(), 5)
        assert runner._judge_hints("processes", "BASE") == "BASE"
