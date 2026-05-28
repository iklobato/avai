"""Tests for the Runner — specifically its enrichment-phase wiring
(``_enrich_entries``) and the cycle's overall sequencing.

The full ``Runner.run_once`` pulls in the collector factory which
needs platform-specific binaries, so we don't drive it end-to-end
here. Instead we build a Runner with hand-rolled fakes and exercise
just the methods that mediate enrichment + judging.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase

from avai.enrichers import (
    Enricher,
    EnrichmentChain,
    Evidence,
    EvidenceCache,
    Indicator,
    IndicatorType,
    VerdictHint,
)
from avai.enrichers.cache import register_schema
from avai.host_monitor import (
    Base,
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
            source       = self.name,
            indicator    = indicator,
            verdict_hint = VerdictHint.MALICIOUS,
            confidence   = 0.9,
            summary      = f"test malicious hit for {indicator.value}",
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sink():
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False})
    s = Sink(engine)
    s.setup()
    return s


@pytest.fixture
def chain(sink):
    return EnrichmentChain([_AlwaysHitEnricher()],
                           EvidenceCache(sink.engine, Base))


# ---------------------------------------------------------------------------
# Runner._enrich_entries — the wiring code
# ---------------------------------------------------------------------------

class TestEnrichEntries:
    def _runner(self, sink, judge, chain):
        return Runner(sink=sink, snapshot_collectors=[], streaming_collectors=[],
                      judge=judge, lookback_min=5, enrichment_chain=chain)

    def test_attaches_evidence_to_each_unjudged_entry(self, sink, chain):
        runner = self._runner(sink, _RecordingJudge(), chain)
        # Two distinct hashes — the chain enriches each via an indicator
        # extracted from `network_connections`. Build rows directly.
        from avai.host_monitor import NetworkConnectionRow
        collector = _StubCollector()
        collector.name = "network_connections"
        collector.model = NetworkConnectionRow
        collector.judge_fields = ("raddr", "pid", "proc_name")

        rows = [{
            "raddr": "8.8.8.8:53", "pid": 1, "proc_name": "dns",
            "username": "u", "status": "ESTABLISHED",
            "run_id": "x", "collected_at": utcnow(),
            "content_hash": content_hash({"raddr": "8.8.8.8:53", "pid": 1,
                                          "proc_name": "dns"},
                                         collector.judge_fields),
        }]
        unjudged = [{"content_hash": rows[0]["content_hash"],
                     "raddr": "8.8.8.8:53", "pid": 1, "proc_name": "dns"}]

        n = runner._enrich_entries(collector, unjudged, rows)
        assert n == 1  # one indicator extracted (8.8.8.8)
        assert "evidence" in unjudged[0]
        assert any(e["src"] == "test_hit" for e in unjudged[0]["evidence"])
        assert unjudged[0]["evidence"][0]["hint"] == "malicious"

    def test_no_chain_means_no_evidence_no_lookups(self, sink):
        runner = Runner(sink, [], [], _RecordingJudge(), 5,
                        enrichment_chain=None)
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
        runner = Runner(sink, [], [], _RecordingJudge(), 5,
                        enrichment_chain=chain)
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
