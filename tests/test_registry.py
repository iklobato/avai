"""Tests for the enricher registry — the env-gated factory that
materialises the default chain."""

from __future__ import annotations

import logging
import os

import pytest
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase

from avai.enrichers import (
    ChainBuilder,
    ChainRequest,
    EnricherCatalog,
    EnrichmentChain,
    EvidenceCache,
)
from avai.enrichers.http import HttpClient


class _Base(DeclarativeBase):
    pass


@pytest.fixture(autouse=True)
def _clear_all_tokens(monkeypatch: pytest.MonkeyPatch):
    """Start each test from a known no-token state so a stale env var
    in the dev shell can't flip a keyed source on."""
    for var in (
        "ABUSE_CH_AUTH_KEY",
        "VT_API_KEY",
        "ABUSEIPDB_API_KEY",
        "GREYNOISE_API_KEY",
        "GOOGLE_SAFE_BROWSING_API_KEY",
        "PHISHTANK_API_KEY",
        "GITHUB_TOKEN",
        "NVD_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    yield


@pytest.fixture
def engine():
    return create_engine("sqlite:///:memory:")


class TestDiscoverEnricherClasses:
    def test_returns_all_known_sources(self) -> None:
        catalog = EnricherCatalog.of_sources(logging.getLogger("test"))
        names = {c.name for c in catalog.classes()}
        # Expected total: 10 keyless + 3 abuse.ch + 6 keyed = 19.
        assert len(names) == 19
        # Spot-check membership.
        assert {"malware_bazaar", "virustotal", "cisa_kev", "ipwhois_geo"}.issubset(
            names
        )

    def test_classes_are_concrete_subclasses_of_enricher(self) -> None:
        from avai.enrichers.base import Enricher

        for cls in EnricherCatalog.of_sources(logging.getLogger("test")).classes():
            assert issubclass(cls, Enricher)
            # No abstract __abstractmethods__ left.
            assert not cls.__abstractmethods__


class TestBuildDefaultChain:
    def build(
        self, engine: Engine, enable: frozenset[str] | None = None
    ) -> EnrichmentChain:
        logger = logging.getLogger("test")
        builder = ChainBuilder(
            EnricherCatalog.of_sources(logger), HttpClient.create(logger), logger
        )
        cache = EvidenceCache.on_base(engine, _Base)
        return builder.build(cache, ChainRequest(dict(os.environ), enable))

    def test_with_no_tokens_only_keyless_sources_register(self, engine) -> None:
        chain = self.build(engine)
        # 10 keyless enrichers; the rest are gated.
        assert sorted(chain.sources) == sorted(
            [
                "circl_hashlookup",
                "shodan_internetdb",
                "feodo_tracker",
                "osv",
                "cisa_kev",
                "nvd",
                "endoflife",
                "crtsh",
                "ipwhois_geo",
                "local_denylist",
            ]
        )

    def test_abuse_ch_key_enables_three_sources(self, engine, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ABUSE_CH_AUTH_KEY", "x")
        chain = self.build(engine)
        for name in ("malware_bazaar", "urlhaus", "threatfox"):
            assert name in chain.sources

    def test_empty_string_token_does_not_enable_source(self, engine, monkeypatch: pytest.MonkeyPatch) -> None:
        # Regression: the env-empty-string fix. `-e VT_API_KEY=` in
        # docker yields "" which must NOT register the enricher.
        monkeypatch.setenv("VT_API_KEY", "")
        chain = self.build(engine)
        assert "virustotal" not in chain.sources

    def test_per_key_gate_is_independent(self, engine, monkeypatch: pytest.MonkeyPatch) -> None:
        # Setting one keyed source's token does not register others.
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "x")
        chain = self.build(engine)
        assert "abuseipdb" in chain.sources
        assert "virustotal" not in chain.sources
        assert "greynoise" not in chain.sources

    def test_enable_allowlist_filters_to_subset(self, engine) -> None:
        chain = self.build(engine, frozenset({"cisa_kev", "osv"}))
        assert sorted(chain.sources) == ["cisa_kev", "osv"]

    def test_enable_allowlist_with_invalid_name_yields_empty(self, engine) -> None:
        chain = self.build(engine, frozenset({"bogus"}))
        assert chain.sources == []

    def test_enable_allowlist_still_respects_env_gate(self, engine, monkeypatch: pytest.MonkeyPatch) -> None:
        # VT_API_KEY unset → even if asked, virustotal must NOT register.
        chain = self.build(engine, frozenset({"virustotal"}))
        assert chain.sources == []

    def test_all_tokens_set_enables_all_sources(self, engine, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in (
            "ABUSE_CH_AUTH_KEY",
            "VT_API_KEY",
            "ABUSEIPDB_API_KEY",
            "GREYNOISE_API_KEY",
            "GOOGLE_SAFE_BROWSING_API_KEY",
            "PHISHTANK_API_KEY",
            "GITHUB_TOKEN",
        ):
            monkeypatch.setenv(var, "fake")
        chain = self.build(engine)
        assert len(chain.sources) == 19
