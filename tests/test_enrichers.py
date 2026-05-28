"""Tests for the enrichment framework.

Network-free: every test uses fake enrichers that record calls. The
real-source modules are import-tested via the registry but their
``_fetch`` methods are never invoked.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

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
    extract_indicators,
)
from avai.enrichers.base import RateLimitedError, worst_hint
from avai.enrichers.cache import register_schema
from avai.enrichers.registry import discover_enricher_classes


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

class _Base(DeclarativeBase):
    pass


@pytest.fixture
def engine_and_base():
    engine = create_engine("sqlite:///:memory:")
    register_schema(_Base)
    _Base.metadata.create_all(engine)
    return engine, _Base


@pytest.fixture
def cache(engine_and_base):
    engine, base = engine_and_base
    return EvidenceCache(engine, base)


def _make_evidence(source: str, ind: Indicator,
                   hint: VerdictHint = VerdictHint.MALICIOUS,
                   summary: str = "test") -> Evidence:
    return Evidence(
        source       = source,
        indicator    = ind,
        verdict_hint = hint,
        confidence   = 0.9,
        summary      = summary,
    )


class _FakeEnricher(Enricher):
    """Records every call and returns a configured response."""

    supports_types = frozenset({IndicatorType.SHA256, IndicatorType.IPV4})
    requires_token = None
    ttl_hours      = 24
    name           = "fake_default"

    def __init__(self, *, return_value: Optional[Evidence] = None,
                 raise_exc: Optional[Exception] = None,
                 name: str = "fake"):
        self.name = name
        self.calls: list[Indicator] = []
        self._return = return_value
        self._exc = raise_exc

    def _fetch(self, indicator):
        self.calls.append(indicator)
        if self._exc is not None:
            raise self._exc
        if self._return is None:
            return None
        return Evidence(
            source       = self.name,
            indicator    = indicator,
            verdict_hint = self._return.verdict_hint,
            confidence   = self._return.confidence,
            summary      = self._return.summary,
            details      = self._return.details,
        )


# ---------------------------------------------------------------------------
# Indicator
# ---------------------------------------------------------------------------

class TestIndicator:
    def test_sha256_is_lowercased(self):
        ind = Indicator(IndicatorType.SHA256, "ABCDEF" + "0" * 58)
        assert ind.value == "abcdef" + "0" * 58

    def test_url_fragment_is_stripped(self):
        ind = Indicator(IndicatorType.URL, "https://e.test/x#hash")
        assert ind.value == "https://e.test/x"

    def test_equality_drives_dedup(self):
        a = Indicator(IndicatorType.IPV4, "1.2.3.4")
        b = Indicator(IndicatorType.IPV4, "1.2.3.4", context={"x": "y"})
        # Frozen dataclass equality ignores nothing — context is part of
        # the hash. Use a set of (type, value) tuples for indicator
        # dedup when context shouldn't matter.
        assert a != b


# ---------------------------------------------------------------------------
# EvidenceCache
# ---------------------------------------------------------------------------

class TestEvidenceCache:
    def test_put_then_get_within_ttl_returns_evidence(self, cache):
        e = _FakeEnricher()
        ind = Indicator(IndicatorType.SHA256, "a" * 64)
        ev = _make_evidence(e.name, ind)
        cache.put(ev)
        got = cache.get(e, ind)
        assert got is not None
        assert got.verdict_hint is VerdictHint.MALICIOUS
        assert got.source == e.name

    def test_get_misses_when_expired(self, cache):
        e = _FakeEnricher()
        e.ttl_hours = 1
        ind = Indicator(IndicatorType.SHA256, "b" * 64)
        ev = Evidence(
            source       = e.name,
            indicator    = ind,
            verdict_hint = VerdictHint.MALICIOUS,
            confidence   = 0.9,
            summary      = "old",
            fetched_at   = datetime.now(timezone.utc) - timedelta(hours=2),
        )
        cache.put(ev)
        assert cache.get(e, ind) is None

    def test_put_upserts(self, cache):
        e = _FakeEnricher()
        ind = Indicator(IndicatorType.SHA256, "c" * 64)
        cache.put(_make_evidence(e.name, ind, summary="first"))
        cache.put(_make_evidence(e.name, ind, summary="second"))
        got = cache.get(e, ind)
        assert got is not None
        assert got.summary == "second"


# ---------------------------------------------------------------------------
# EnrichmentChain
# ---------------------------------------------------------------------------

class TestEnrichmentChain:
    def test_skips_unsupported_indicator_type(self, cache):
        e = _FakeEnricher(name="e1",
                          return_value=_make_evidence("e1",
                              Indicator(IndicatorType.SHA256, "0"*64)))
        chain = EnrichmentChain([e], cache)
        # URL type → not in e.supports_types.
        out = chain.enrich(Indicator(IndicatorType.URL, "https://x/"))
        assert out == []
        assert e.calls == []

    def test_returns_evidence_from_supporting_enricher(self, cache):
        ind = Indicator(IndicatorType.IPV4, "1.2.3.4")
        e = _FakeEnricher(name="e1",
                          return_value=_make_evidence("e1", ind))
        chain = EnrichmentChain([e], cache)
        out = chain.enrich(ind)
        assert len(out) == 1
        assert out[0].source == "e1"

    def test_second_call_hits_cache(self, cache):
        ind = Indicator(IndicatorType.IPV4, "1.2.3.4")
        e = _FakeEnricher(name="e1",
                          return_value=_make_evidence("e1", ind))
        chain = EnrichmentChain([e], cache)
        chain.enrich(ind)
        chain.enrich(ind)  # should serve from cache
        assert len(e.calls) == 1

    def test_rate_limit_is_swallowed(self, cache):
        ind = Indicator(IndicatorType.IPV4, "1.2.3.4")
        e_bad = _FakeEnricher(name="bad",
                              raise_exc=RateLimitedError("over"))
        e_good = _FakeEnricher(name="good",
                               return_value=_make_evidence("good", ind))
        chain = EnrichmentChain([e_bad, e_good], cache)
        out = chain.enrich(ind)
        # One bad source must not block the good one.
        assert [ev.source for ev in out] == ["good"]
        # And the bad source was tallied as rate_limited.
        assert chain.stats()["bad"]["rate_limited"] == 1

    def test_unexpected_exception_does_not_propagate(self, cache):
        ind = Indicator(IndicatorType.IPV4, "1.2.3.4")
        e_bad = _FakeEnricher(name="bad",
                              raise_exc=RuntimeError("boom"))
        e_good = _FakeEnricher(name="good",
                               return_value=_make_evidence("good", ind))
        chain = EnrichmentChain([e_bad, e_good], cache)
        out = chain.enrich(ind)
        assert [ev.source for ev in out] == ["good"]
        assert chain.stats()["bad"]["error"] == 1

    def test_none_response_is_not_cached(self, cache):
        ind = Indicator(IndicatorType.IPV4, "1.2.3.4")
        e = _FakeEnricher(name="e1", return_value=None)
        chain = EnrichmentChain([e], cache)
        chain.enrich(ind)
        chain.enrich(ind)
        # Two real fetches because a None response means "no opinion",
        # not "definitely nothing" — we want a chance to learn later.
        assert len(e.calls) == 2


# ---------------------------------------------------------------------------
# Indicator extraction
# ---------------------------------------------------------------------------

class TestIndicatorExtraction:
    def test_quarantine_url_yields_url_and_domain(self):
        out = extract_indicators("quarantine_events", {
            "origin_url": "https://evil.example.com/dropper.exe",
        })
        types = sorted(str(i.type) for i in out)
        assert types == ["domain", "url"]

    def test_installed_apps_yields_package(self):
        out = extract_indicators("installed_apps", {
            "name": "openssl", "version": "3.0.2"
        })
        assert len(out) == 1
        assert out[0].type is IndicatorType.PACKAGE
        assert out[0].value == "openssl@3.0.2"

    def test_network_connections_skips_private_ip(self):
        out = extract_indicators("network_connections", {
            "raddr": "127.0.0.1:8000",
        })
        assert out == []

    def test_network_connections_emits_public_ip(self):
        out = extract_indicators("network_connections", {
            "raddr": "8.8.8.8:443",
        })
        assert len(out) == 1
        assert out[0].type is IndicatorType.IPV4
        assert out[0].value == "8.8.8.8"

    def test_unknown_collector_yields_nothing(self):
        out = extract_indicators("not_a_real_collector", {"x": 1})
        assert out == []

    def test_browser_extension_normalises_wildcards(self):
        out = extract_indicators("browser_extensions", {
            "host_permissions_json": '["https://*.malsite.test/*"]',
        })
        assert [i.value for i in out] == ["malsite.test"]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class TestRegistry:
    def test_discovers_at_least_the_advertised_sources(self):
        names = {c.name for c in discover_enricher_classes()}
        # The 17 we shipped — assert presence so a missing source
        # surfaces as a test failure rather than a silent regression.
        expected = {
            "malware_bazaar", "circl_hashlookup", "shodan_internetdb",
            "urlhaus", "feodo_tracker", "threatfox",
            "osv", "cisa_kev", "nvd", "endoflife", "crtsh",
            "virustotal", "abuseipdb", "greynoise", "safe_browsing",
            "phishtank", "github_advisory",
        }
        missing = expected - names
        assert not missing, f"missing enrichers: {missing}"

    def test_from_env_skips_when_token_missing(self, monkeypatch):
        # Pick any keyed source.
        from avai.enrichers.sources.virustotal import VirusTotalEnricher
        monkeypatch.delenv("VT_API_KEY", raising=False)
        assert VirusTotalEnricher.from_env() is None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestWorstHint:
    def test_malicious_beats_everything(self):
        assert worst_hint([
            VerdictHint.BENIGN,
            VerdictHint.SUSPICIOUS,
            VerdictHint.MALICIOUS,
        ]) is VerdictHint.MALICIOUS

    def test_empty_input_is_unknown(self):
        assert worst_hint([]) is VerdictHint.UNKNOWN
