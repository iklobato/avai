"""Tests for the enricher registry — the env-gated factory that
materialises the default chain."""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase

from avai.enrichers.registry import build_default_chain, discover_enricher_classes


class _Base(DeclarativeBase):
    pass


@pytest.fixture(autouse=True)
def _clear_all_tokens(monkeypatch):
    """Start each test from a known no-token state so a stale env var
    in the dev shell can't flip a keyed source on."""
    for var in (
        "ABUSE_CH_AUTH_KEY", "VT_API_KEY", "ABUSEIPDB_API_KEY",
        "GREYNOISE_API_KEY", "GOOGLE_SAFE_BROWSING_API_KEY",
        "PHISHTANK_API_KEY", "GITHUB_TOKEN", "NVD_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    yield


@pytest.fixture
def engine():
    return create_engine("sqlite:///:memory:")


class TestDiscoverEnricherClasses:
    def test_returns_all_known_sources(self):
        names = {c.name for c in discover_enricher_classes()}
        # Expected total: 8 keyless + 3 abuse.ch + 6 keyed = 17.
        assert len(names) == 17
        # Spot-check membership.
        assert {"malware_bazaar", "virustotal", "cisa_kev"}.issubset(names)

    def test_classes_are_concrete_subclasses_of_enricher(self):
        from avai.enrichers.base import Enricher
        for cls in discover_enricher_classes():
            assert issubclass(cls, Enricher)
            # No abstract __abstractmethods__ left.
            assert not cls.__abstractmethods__


class TestBuildDefaultChain:
    def test_with_no_tokens_only_keyless_sources_register(self, engine):
        chain = build_default_chain(engine, _Base)
        # 8 keyless enrichers; the rest are gated.
        assert sorted(chain.sources) == sorted([
            "circl_hashlookup", "shodan_internetdb", "feodo_tracker",
            "osv", "cisa_kev", "nvd", "endoflife", "crtsh",
        ])

    def test_abuse_ch_key_enables_three_sources(self, engine, monkeypatch):
        monkeypatch.setenv("ABUSE_CH_AUTH_KEY", "x")
        chain = build_default_chain(engine, _Base)
        for name in ("malware_bazaar", "urlhaus", "threatfox"):
            assert name in chain.sources

    def test_empty_string_token_does_not_enable_source(self, engine, monkeypatch):
        # Regression: the env-empty-string fix. `-e VT_API_KEY=` in
        # docker yields "" which must NOT register the enricher.
        monkeypatch.setenv("VT_API_KEY", "")
        chain = build_default_chain(engine, _Base)
        assert "virustotal" not in chain.sources

    def test_per_key_gate_is_independent(self, engine, monkeypatch):
        # Setting one keyed source's token does not register others.
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "x")
        chain = build_default_chain(engine, _Base)
        assert "abuseipdb" in chain.sources
        assert "virustotal" not in chain.sources
        assert "greynoise" not in chain.sources

    def test_enable_allowlist_filters_to_subset(self, engine):
        chain = build_default_chain(engine, _Base,
                                    enable=["cisa_kev", "osv"])
        assert sorted(chain.sources) == ["cisa_kev", "osv"]

    def test_enable_allowlist_with_invalid_name_yields_empty(self, engine):
        chain = build_default_chain(engine, _Base, enable=["bogus"])
        assert chain.sources == []

    def test_enable_allowlist_still_respects_env_gate(self, engine, monkeypatch):
        # VT_API_KEY unset → even if asked, virustotal must NOT register.
        chain = build_default_chain(engine, _Base, enable=["virustotal"])
        assert chain.sources == []

    def test_all_tokens_set_enables_all_sources(self, engine, monkeypatch):
        for var in (
            "ABUSE_CH_AUTH_KEY", "VT_API_KEY", "ABUSEIPDB_API_KEY",
            "GREYNOISE_API_KEY", "GOOGLE_SAFE_BROWSING_API_KEY",
            "PHISHTANK_API_KEY", "GITHUB_TOKEN",
        ):
            monkeypatch.setenv(var, "fake")
        chain = build_default_chain(engine, _Base)
        assert len(chain.sources) == 17
