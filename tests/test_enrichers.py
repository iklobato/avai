"""Tests for the enrichment framework.

Network-free: every test uses fake enrichers that record calls. The
real-source modules are import-tested via the registry but their
``_fetch`` methods are never invoked.
"""

from __future__ import annotations

import gc
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase

from avai.enrichers import (
    Enricher,
    EnricherCatalog,
    EnrichmentChain,
    EnrichmentSchema,
    Evidence,
    EvidenceCache,
    Indicator,
    IndicatorExtraction,
    IndicatorType,
    VerdictHint,
)
from avai.enrichers.base import EnricherError, RateLimitedError
from avai.enrichers.http import HttpClient

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class _Base(DeclarativeBase):
    pass


@pytest.fixture
def engine_and_base():
    engine = create_engine("sqlite:///:memory:")
    EnrichmentSchema(_Base).model()
    _Base.metadata.create_all(engine)
    return engine, _Base


@pytest.fixture
def cache(engine_and_base):
    engine, base = engine_and_base
    return EvidenceCache.on_base(engine, base)


def _make_evidence(
    source: str,
    ind: Indicator,
    hint: VerdictHint = VerdictHint.MALICIOUS,
    summary: str = "test",
) -> Evidence:
    return Evidence(
        source=source,
        indicator=ind,
        verdict_hint=hint,
        confidence=0.9,
        summary=summary,
    )


class _FakeEnricher(Enricher):
    """Records every call and returns a configured response."""

    supports_types = frozenset({IndicatorType.SHA256, IndicatorType.IPV4})
    requires_token = None
    ttl_hours = 24
    name = "fake_default"

    def __init__(
        self,
        *,
        return_value: Optional[Evidence] = None,
        raise_exc: Optional[Exception] = None,
        name: str = "fake",
    ):
        self.name = name
        self.calls: list[Indicator] = []
        self._return = return_value
        self._exc = raise_exc

    def fetch(self, indicator: Indicator) -> Evidence | None:
        self.calls.append(indicator)
        if self._exc is not None:
            raise self._exc
        if self._return is None:
            return None
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=self._return.verdict_hint,
            confidence=self._return.confidence,
            summary=self._return.summary,
            details=self._return.details,
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


# ---------------------------------------------------------------------------
# EvidenceCache
# ---------------------------------------------------------------------------


class TestEnrichmentSchema:
    def test_model_is_remapped_after_the_first_class_is_collected(self) -> None:
        class _FreshBase(DeclarativeBase):
            pass

        EnrichmentSchema(_FreshBase).model()
        gc.collect()

        model = EnrichmentSchema(_FreshBase).model()

        assert model.__table__ is _FreshBase.metadata.tables["enrichment_evidence"]


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
            source=e.name,
            indicator=ind,
            verdict_hint=VerdictHint.MALICIOUS,
            confidence=0.9,
            summary="old",
            fetched_at=datetime.now(timezone.utc) - timedelta(hours=2),
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
        e = _FakeEnricher(
            name="e1",
            return_value=_make_evidence(
                "e1", Indicator(IndicatorType.SHA256, "0" * 64)
            ),
        )
        chain = EnrichmentChain([e], cache, logging.getLogger("test"))
        # URL type → not in e.supports_types.
        out = chain.enrich(Indicator(IndicatorType.URL, "https://x/"))
        assert out == []
        assert e.calls == []

    def test_returns_evidence_from_supporting_enricher(self, cache):
        ind = Indicator(IndicatorType.IPV4, "1.2.3.4")
        e = _FakeEnricher(name="e1", return_value=_make_evidence("e1", ind))
        chain = EnrichmentChain([e], cache, logging.getLogger("test"))
        out = chain.enrich(ind)
        assert len(out) == 1
        assert out[0].source == "e1"

    def test_second_call_hits_cache(self, cache):
        ind = Indicator(IndicatorType.IPV4, "1.2.3.4")
        e = _FakeEnricher(name="e1", return_value=_make_evidence("e1", ind))
        chain = EnrichmentChain([e], cache, logging.getLogger("test"))
        chain.enrich(ind)
        chain.enrich(ind)  # should serve from cache
        assert len(e.calls) == 1

    def test_rate_limit_is_swallowed(self, cache):
        ind = Indicator(IndicatorType.IPV4, "1.2.3.4")
        e_bad = _FakeEnricher(name="bad", raise_exc=RateLimitedError("over"))
        e_good = _FakeEnricher(name="good", return_value=_make_evidence("good", ind))
        chain = EnrichmentChain([e_bad, e_good], cache, logging.getLogger("test"))
        out = chain.enrich(ind)
        # One bad source must not block the good one.
        assert [ev.source for ev in out] == ["good"]

    def test_source_error_is_swallowed(self, cache):
        ind = Indicator(IndicatorType.IPV4, "1.2.3.4")
        e_bad = _FakeEnricher(name="bad", raise_exc=EnricherError("http 500"))
        e_good = _FakeEnricher(name="good", return_value=_make_evidence("good", ind))
        chain = EnrichmentChain([e_bad, e_good], cache, logging.getLogger("test"))
        out = chain.enrich(ind)
        assert [ev.source for ev in out] == ["good"]

    def test_malformed_payload_error_does_not_propagate(
        self, cache: EvidenceCache
    ) -> None:
        ind = Indicator(IndicatorType.IPV4, "1.2.3.4")
        e_bad = _FakeEnricher(name="bad", raise_exc=KeyError("data"))
        e_good = _FakeEnricher(name="good", return_value=_make_evidence("good", ind))
        chain = EnrichmentChain([e_bad, e_good], cache, logging.getLogger("test"))
        out = chain.enrich(ind)
        assert [ev.source for ev in out] == ["good"]

    def test_programming_error_in_a_source_propagates(
        self, cache: EvidenceCache
    ) -> None:
        ind = Indicator(IndicatorType.IPV4, "1.2.3.4")
        e_bad = _FakeEnricher(name="bad", raise_exc=RuntimeError("bug"))
        chain = EnrichmentChain([e_bad], cache, logging.getLogger("test"))
        with pytest.raises(RuntimeError, match="bug"):
            chain.enrich(ind)

    def test_none_response_is_not_cached(self, cache):
        ind = Indicator(IndicatorType.IPV4, "1.2.3.4")
        e = _FakeEnricher(name="e1", return_value=None)
        chain = EnrichmentChain([e], cache, logging.getLogger("test"))
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
        out = IndicatorExtraction.default().extract(
            "quarantine_events",
            {
                "origin_url": "https://evil.example.com/dropper.exe",
            },
        )
        types = sorted(str(i.type) for i in out)
        assert types == ["domain", "url"]

    def test_installed_apps_yields_package(self):
        out = IndicatorExtraction.default().extract(
            "installed_apps", {"name": "openssl", "version": "3.0.2"}
        )
        assert len(out) == 1
        assert out[0].type is IndicatorType.PACKAGE
        assert out[0].value == "openssl@3.0.2"

    def test_network_connections_skips_private_ip(self):
        out = IndicatorExtraction.default().extract(
            "network_connections",
            {
                "raddr": "127.0.0.1:8000",
            },
        )
        assert out == []

    def test_network_connections_emits_public_ip(self):
        out = IndicatorExtraction.default().extract(
            "network_connections",
            {
                "raddr": "8.8.8.8:443",
            },
        )
        assert len(out) == 1
        assert out[0].type is IndicatorType.IPV4
        assert out[0].value == "8.8.8.8"

    def test_network_connections_emits_from_raddr_ip_fields(self):
        # The real collector emits raddr_ip/raddr_port (not a combined raddr
        # string); enrichment must read those so the remote IP gets intel.
        out = IndicatorExtraction.default().extract(
            "network_connections",
            {"raddr_ip": "1.2.3.4", "raddr_port": 4444, "status": "ESTABLISHED"},
        )
        assert len(out) == 1
        assert out[0].type is IndicatorType.IPV4
        assert out[0].value == "1.2.3.4"

    def test_network_connections_private_raddr_ip_skipped(self):
        out = IndicatorExtraction.default().extract(
            "network_connections",
            {"raddr_ip": "10.0.0.5", "raddr_port": 22, "status": "ESTABLISHED"},
        )
        assert out == []

    def test_network_connections_no_remote_yields_nothing(self):
        out = IndicatorExtraction.default().extract(
            "network_connections",
            {"raddr_ip": None, "raddr_port": None, "status": "LISTEN"},
        )
        assert out == []

    def test_unknown_collector_yields_nothing(self):
        out = IndicatorExtraction.default().extract("not_a_real_collector", {"x": 1})
        assert out == []

    def test_browser_extension_normalises_wildcards(self):
        out = IndicatorExtraction.default().extract(
            "browser_extensions",
            {
                "host_permissions_json": '["https://*.malsite.test/*"]',
            },
        )
        assert [i.value for i in out] == ["malsite.test"]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_discovers_at_least_the_advertised_sources(self):
        catalog = EnricherCatalog.of_sources(logging.getLogger("test"))
        names = {c.name for c in catalog.classes()}
        # The 17 we shipped — assert presence so a missing source
        # surfaces as a test failure rather than a silent regression.
        expected = {
            "malware_bazaar",
            "circl_hashlookup",
            "shodan_internetdb",
            "urlhaus",
            "feodo_tracker",
            "threatfox",
            "osv",
            "cisa_kev",
            "nvd",
            "endoflife",
            "crtsh",
            "virustotal",
            "abuseipdb",
            "greynoise",
            "safe_browsing",
            "phishtank",
            "github_advisory",
        }
        missing = expected - names
        assert not missing, f"missing enrichers: {missing}"

    def test_from_env_skips_when_token_missing(self, monkeypatch):
        # Pick any keyed source.
        from avai.enrichers.sources.virustotal import VirusTotalEnricher

        http = HttpClient.create(logging.getLogger("test"))
        assert VirusTotalEnricher.create(http, {}) is None

    def test_from_env_skips_when_token_set_to_empty(self, monkeypatch):
        # ``docker run -e VT_API_KEY=`` produces an empty string in
        # the container — should be treated as "missing", not "present".
        from avai.enrichers.sources.virustotal import VirusTotalEnricher

        env = {"VT_API_KEY": ""}
        http = HttpClient.create(logging.getLogger("test"))
        assert VirusTotalEnricher.env_token(env) is None
        assert VirusTotalEnricher.create(http, env) is None

    def test_keyless_enricher_always_registers(self, monkeypatch):
        from avai.enrichers.sources.cisa_kev import CisaKevEnricher

        # No env var matters for a keyless source.
        assert CisaKevEnricher.env_token({}) is not None
        assert CisaKevEnricher.env_token({})  # truthy sentinel


# ---------------------------------------------------------------------------
# Forward-chaining: discovered CVE IDs get re-enriched through CVE sources
# ---------------------------------------------------------------------------


class TestForwardChain:
    def test_discovered_cves_are_forward_chained(self, cache):
        from avai.enrichers import (
            Enricher,
            EnrichmentChain,
            Evidence,
            Indicator,
            IndicatorType,
            VerdictHint,
        )

        class _Pkg(Enricher):
            name = "osv_like"
            supports_types = frozenset({IndicatorType.PACKAGE})
            requires_token = None
            CONFIDENCE = 0.75

            def fetch(self, ind: Indicator) -> Evidence:
                return Evidence(
                    source=self.name,
                    indicator=ind,
                    verdict_hint=VerdictHint.SUSPICIOUS,
                    confidence=self.CONFIDENCE,
                    summary="hit",
                    details={"vuln_ids": ["CVE-2024-0001"]},
                )

        class _Cve(Enricher):
            name = "nvd_like"
            supports_types = frozenset({IndicatorType.CVE})
            requires_token = None

            CONFIDENCE = 0.9
            BASE_SCORE = 9.8

            def __init__(self):
                self.calls = []

            def fetch(self, ind: Indicator) -> Evidence:
                self.calls.append(ind.value)
                return Evidence(
                    source=self.name,
                    indicator=ind,
                    verdict_hint=VerdictHint.MALICIOUS,
                    confidence=self.CONFIDENCE,
                    summary=f"CVSS {self.BASE_SCORE}",
                    details={"cvss31": {"baseScore": self.BASE_SCORE}},
                )

        cve = _Cve()
        chain = EnrichmentChain(
            [_Pkg(HttpClient.create(logging.getLogger("test")), ""), cve],
            cache,
            logging.getLogger("test"),
        )
        out = chain.enrich(Indicator(IndicatorType.PACKAGE, "openssl@3.0.2"))
        # forward-chained (Indicator normalises the value to lowercase)
        assert [c.lower() for c in cve.calls] == ["cve-2024-0001"]
        srcs = {e.source for e in out}
        assert "osv_like" in srcs and "nvd_like" in srcs

    def test_forward_chain_dedups_filters_and_caps_ids(self, cache):
        from avai.enrichers import (
            Enricher,
            EnrichmentChain,
            Evidence,
            Indicator,
            IndicatorType,
            VerdictHint,
        )

        many = [f"CVE-2024-{n:04d}" for n in range(2, 14)]
        vuln_ids = ["cve-2024-0001", "PYSEC-2024-1", "GHSA-aaaa", "ghsa-AAAA"]

        def evidence(source, ind, details):
            return Evidence(
                source=source,
                indicator=ind,
                verdict_hint=VerdictHint.SUSPICIOUS,
                confidence=0.5,
                summary="x",
                details=details,
            )

        class _Pkg(Enricher):
            name = "pkg"
            supports_types = frozenset({IndicatorType.PACKAGE})
            requires_token = None

            def fetch(self, ind: Indicator) -> Evidence:
                return evidence(self.name, ind, {"vuln_ids": vuln_ids + many})

        class _Cve(Enricher):
            name = "cve"
            supports_types = frozenset({IndicatorType.CVE})
            requires_token = None

            def __init__(self):
                self.calls = []

            def fetch(self, ind: Indicator) -> Evidence:
                self.calls.append(ind.value.upper())
                return evidence(self.name, ind, {})

        cve = _Cve()
        out = EnrichmentChain(
            [_Pkg(HttpClient.create(logging.getLogger("test")), ""), cve],
            cache,
            logging.getLogger("test"),
        ).enrich(Indicator(IndicatorType.PACKAGE, "openssl@3.0.2"))
        expected = ["CVE-2024-0001", "GHSA-AAAA", *many[:8]]
        assert cve.calls == expected
        assert [e.source for e in out] == ["pkg"] + ["cve"] * len(expected)

    def test_cve_indicator_does_not_recurse(self, cache):
        from avai.enrichers import (
            Enricher,
            EnrichmentChain,
            Evidence,
            Indicator,
            IndicatorType,
            VerdictHint,
        )

        class _SelfRef(Enricher):
            name = "self_ref"
            supports_types = frozenset({IndicatorType.CVE})
            requires_token = None

            CONFIDENCE = 0.5

            def __init__(self):
                self.n = 0

            def fetch(self, ind: Indicator) -> Evidence:
                self.n += 1
                return Evidence(
                    source=self.name,
                    indicator=ind,
                    verdict_hint=VerdictHint.SUSPICIOUS,
                    confidence=self.CONFIDENCE,
                    summary="x",
                    details={"vuln_ids": [ind.value]},
                )

        e = _SelfRef()
        EnrichmentChain([e], cache, logging.getLogger("test")).enrich(
            Indicator(IndicatorType.CVE, "CVE-2024-0001")
        )
        assert e.n == 1  # CVE indicators don't forward-chain → no recursion
