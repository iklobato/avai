"""Mocked-HTTP tests for the remaining enricher sources.

Complements :mod:`test_enricher_sources` — same fake-HTTP harness,
covers the 10 sources not exercised there: URLhaus, ThreatFox, Feodo
Tracker (cached-feed flow), NVD, GitHub Advisory, GreyNoise, Google
Safe Browsing, PhishTank, endoflife.date, crt.sh.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from avai.enrichers.base import (
    EnricherError,
    Indicator,
    IndicatorType,
    RateLimitedError,
    VerdictHint,
)

# -- Shared fake HTTP plumbing (kept local to avoid cross-file import) ------


class _FakeResp:
    def __init__(self, status: int = 200, json_body: Any = None, text: str = ""):
        self.status_code = status
        self._json = json_body
        self.text = text or (json.dumps(json_body) if json_body is not None else "")
        self.headers: dict[str, str] = {}

    def json(self):
        if self._json is None:
            raise ValueError("no json body")
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeHttp:
    def __init__(self, response: _FakeResp = None, responses: list[_FakeResp] = None):
        self._fixed = response
        self._queue = list(responses or [])
        self.calls: list[tuple[str, str, dict]] = []

    def _next(self):
        if self._queue:
            return self._queue.pop(0)
        if self._fixed is not None:
            return self._fixed
        raise AssertionError("FakeHttp exhausted")

    def get(self, url, **kw):
        self.calls.append(("GET", url, kw))
        return self._next()

    def post(self, url, **kw):
        self.calls.append(("POST", url, kw))
        return self._next()

    def set_rate(self, host, rate):
        pass


# ---------------------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------------------


class TestURLhaus:
    def _enricher(self, http, monkeypatch):
        monkeypatch.setenv("ABUSE_CH_AUTH_KEY", "fake")
        from avai.enrichers.sources.urlhaus import URLhausEnricher

        return URLhausEnricher(http=http)

    def test_url_hit_returns_malicious(self, monkeypatch):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "query_status": "ok",
                    "threat": "malware_download",
                    "tags": ["emotet"],
                    "date_added": "2024-01-01",
                }
            )
        )
        e = self._enricher(http, monkeypatch)
        ev = e._fetch(Indicator(IndicatorType.URL, "https://evil.test/x"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.MALICIOUS
        assert "emotet" in ev.summary

    def test_domain_hit_uses_host_endpoint(self, monkeypatch):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "query_status": "ok",
                    "threat": "malware",
                }
            )
        )
        e = self._enricher(http, monkeypatch)
        e._fetch(Indicator(IndicatorType.DOMAIN, "evil.test"))
        method, url, kw = http.calls[0]
        assert method == "POST"
        assert url.endswith("/host/")
        assert kw["data"]["host"] == "evil.test"

    def test_no_results_returns_none(self, monkeypatch):
        http = _FakeHttp(_FakeResp(json_body={"query_status": "no_results"}))
        e = self._enricher(http, monkeypatch)
        assert e._fetch(Indicator(IndicatorType.URL, "https://ok.test/")) is None

    def test_host_hit_with_urls_is_suspicious(self, monkeypatch):
        # Regression: the /host/ response has no top-level threat/tags; it
        # carries url_count/firstseen. A host with malware URLs is reported
        # SUSPICIOUS (not a fabricated MALICIOUS with empty fields).
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "query_status": "ok",
                    "url_count": "3",
                    "firstseen": "2024-02-02",
                }
            )
        )
        e = self._enricher(http, monkeypatch)
        ev = e._fetch(Indicator(IndicatorType.DOMAIN, "evil.test"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.SUSPICIOUS
        assert "3 malware URL" in ev.summary

    def test_host_known_but_zero_urls_returns_none(self, monkeypatch):
        # "ok" only means URLhaus knows the host; zero URLs is not actionable.
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "query_status": "ok",
                    "url_count": 0,
                }
            )
        )
        e = self._enricher(http, monkeypatch)
        assert e._fetch(Indicator(IndicatorType.DOMAIN, "known.test")) is None


# ---------------------------------------------------------------------------
# ThreatFox
# ---------------------------------------------------------------------------


class TestThreatFox:
    def _enricher(self, http, monkeypatch):
        monkeypatch.setenv("ABUSE_CH_AUTH_KEY", "fake")
        from avai.enrichers.sources.threatfox import ThreatFoxEnricher

        return ThreatFoxEnricher(http=http)

    def test_hit_returns_malicious(self, monkeypatch):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "query_status": "ok",
                    "data": [
                        {
                            "malware": "Cobalt Strike",
                            "threat_type": "botnet_cc",
                            "first_seen": "2024-01-01",
                        }
                    ],
                }
            )
        )
        e = self._enricher(http, monkeypatch)
        ev = e._fetch(Indicator(IndicatorType.IPV4, "1.2.3.4"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.MALICIOUS
        assert "Cobalt Strike" in ev.summary

    def test_empty_data_array_returns_none(self, monkeypatch):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "query_status": "ok",
                    "data": [],
                }
            )
        )
        e = self._enricher(http, monkeypatch)
        assert e._fetch(Indicator(IndicatorType.IPV4, "1.2.3.4")) is None


# ---------------------------------------------------------------------------
# Feodo Tracker — cached-feed flow
# ---------------------------------------------------------------------------


class TestFeodoTracker:
    def _enricher(self, http):
        from avai.enrichers.sources.feodo_tracker import FeodoTrackerEnricher

        # Reset class-level cache so tests don't bleed.
        FeodoTrackerEnricher._feed = {}
        FeodoTrackerEnricher._feed_ts = 0.0
        return FeodoTrackerEnricher(http=http)

    def test_ip_in_feed_returns_malicious(self):
        http = _FakeHttp(
            _FakeResp(
                json_body=[
                    {
                        "ip_address": "9.9.9.9",
                        "malware": "Emotet",
                        "port": 8080,
                        "first_seen": "2024-05-01",
                    },
                ]
            )
        )
        e = self._enricher(http)
        ev = e._fetch(Indicator(IndicatorType.IPV4, "9.9.9.9"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.MALICIOUS
        assert "Emotet" in ev.summary

    def test_ip_not_in_feed_returns_none(self):
        http = _FakeHttp(
            _FakeResp(
                json_body=[
                    {"ip_address": "9.9.9.9", "malware": "Emotet"},
                ]
            )
        )
        e = self._enricher(http)
        assert e._fetch(Indicator(IndicatorType.IPV4, "1.1.1.1")) is None

    def test_feed_is_only_fetched_once_per_ttl(self):
        # Two consecutive lookups should share the same feed download.
        http = _FakeHttp(
            _FakeResp(
                json_body=[
                    {"ip_address": "9.9.9.9", "malware": "X"},
                ]
            )
        )
        e = self._enricher(http)
        e._fetch(Indicator(IndicatorType.IPV4, "9.9.9.9"))
        e._fetch(Indicator(IndicatorType.IPV4, "9.9.9.9"))
        assert len(http.calls) == 1


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------


class TestNvd:
    def _enricher(self, http):
        from avai.enrichers.sources.nvd import NvdEnricher

        return NvdEnricher(http=http)

    def test_high_cvss_yields_malicious(self):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "vulnerabilities": [
                        {
                            "cve": {
                                "metrics": {
                                    "cvssMetricV31": [
                                        {
                                            "cvssData": {
                                                "baseScore": 9.8,
                                                "baseSeverity": "CRITICAL",
                                            }
                                        }
                                    ]
                                },
                                "descriptions": [{"lang": "en", "value": "RCE"}],
                            },
                        }
                    ]
                }
            )
        )
        e = self._enricher(http)
        ev = e._fetch(Indicator(IndicatorType.CVE, "CVE-2024-1"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.MALICIOUS

    def test_mid_cvss_yields_suspicious(self):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "vulnerabilities": [
                        {
                            "cve": {
                                "metrics": {
                                    "cvssMetricV31": [
                                        {
                                            "cvssData": {
                                                "baseScore": 7.5,
                                                "baseSeverity": "HIGH",
                                            }
                                        }
                                    ]
                                },
                                "descriptions": [{"lang": "en", "value": "DoS"}],
                            },
                        }
                    ]
                }
            )
        )
        e = self._enricher(http)
        ev = e._fetch(Indicator(IndicatorType.CVE, "CVE-2024-2"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.SUSPICIOUS

    def test_empty_vulnerabilities_returns_none(self):
        http = _FakeHttp(_FakeResp(json_body={"vulnerabilities": []}))
        e = self._enricher(http)
        assert e._fetch(Indicator(IndicatorType.CVE, "CVE-1999-0")) is None

    def test_403_is_surfaced_as_rate_limited(self):
        # Regression: NVD returns 403 when the rate window is exceeded;
        # it must become a RateLimitedError so the chain backs off rather
        # than recording a silent no-opinion on every CVE under load.
        http = _FakeHttp(_FakeResp(status=403))
        e = self._enricher(http)
        with pytest.raises(RateLimitedError):
            e._fetch(Indicator(IndicatorType.CVE, "CVE-2024-1"))


# ---------------------------------------------------------------------------
# GitHub Advisory
# ---------------------------------------------------------------------------


class TestGitHubAdvisory:
    def _enricher(self, http, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "fake")
        from avai.enrichers.sources.github_advisory import GitHubAdvisoryEnricher

        return GitHubAdvisoryEnricher(http=http)

    def test_critical_severity_yields_malicious(self, monkeypatch):
        http = _FakeHttp(
            _FakeResp(
                json_body=[
                    {
                        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
                        "summary": "Remote code execution",
                        "severity": "critical",
                        "cvss": {"score": 9.8},
                    }
                ]
            )
        )
        e = self._enricher(http, monkeypatch)
        ev = e._fetch(Indicator(IndicatorType.CVE, "CVE-2024-1"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.MALICIOUS

    def test_high_severity_yields_suspicious(self, monkeypatch):
        http = _FakeHttp(
            _FakeResp(
                json_body=[
                    {
                        "summary": "x",
                        "severity": "high",
                        "cvss": {"score": 7.5},
                    }
                ]
            )
        )
        e = self._enricher(http, monkeypatch)
        ev = e._fetch(Indicator(IndicatorType.CVE, "CVE-2024-2"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.SUSPICIOUS

    def test_empty_advisory_list_returns_none(self, monkeypatch):
        http = _FakeHttp(_FakeResp(json_body=[]))
        e = self._enricher(http, monkeypatch)
        assert e._fetch(Indicator(IndicatorType.CVE, "CVE-0")) is None


# ---------------------------------------------------------------------------
# GreyNoise
# ---------------------------------------------------------------------------


class TestGreyNoise:
    def _enricher(self, http, monkeypatch):
        monkeypatch.setenv("GREYNOISE_API_KEY", "fake")
        from avai.enrichers.sources.greynoise import GreyNoiseEnricher

        return GreyNoiseEnricher(http=http)

    def test_classification_malicious_returns_malicious(self, monkeypatch):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "classification": "malicious",
                    "noise": True,
                    "riot": False,
                    "name": "Mirai botnet",
                }
            )
        )
        e = self._enricher(http, monkeypatch)
        ev = e._fetch(Indicator(IndicatorType.IPV4, "1.2.3.4"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.MALICIOUS

    def test_riot_flag_means_benign(self, monkeypatch):
        # RIOT = "known benign service" (e.g. Google DNS)
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "classification": "benign",
                    "noise": False,
                    "riot": True,
                    "name": "Google",
                }
            )
        )
        e = self._enricher(http, monkeypatch)
        ev = e._fetch(Indicator(IndicatorType.IPV4, "8.8.8.8"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.BENIGN

    def test_noise_only_yields_suspicious(self, monkeypatch):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "classification": "unknown",
                    "noise": True,
                    "riot": False,
                }
            )
        )
        e = self._enricher(http, monkeypatch)
        ev = e._fetch(Indicator(IndicatorType.IPV4, "1.2.3.4"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.SUSPICIOUS

    def test_404_returns_none(self, monkeypatch):
        http = _FakeHttp(_FakeResp(status=404))
        e = self._enricher(http, monkeypatch)
        assert e._fetch(Indicator(IndicatorType.IPV4, "1.2.3.4")) is None

    def test_client_error_raises_not_swallowed(self, monkeypatch):
        # Regression: 400 (and other non-404 client errors like a bad key)
        # used to be silently treated as no-opinion, masking misconfig.
        http = _FakeHttp(_FakeResp(status=400))
        e = self._enricher(http, monkeypatch)
        with pytest.raises(EnricherError):
            e._fetch(Indicator(IndicatorType.IPV4, "1.2.3.4"))


# ---------------------------------------------------------------------------
# Google Safe Browsing
# ---------------------------------------------------------------------------


class TestSafeBrowsing:
    def _enricher(self, http, monkeypatch):
        monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "fake")
        from avai.enrichers.sources.safe_browsing import SafeBrowsingEnricher

        return SafeBrowsingEnricher(http=http)

    def test_matches_yields_malicious(self, monkeypatch):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "matches": [{"threatType": "MALWARE"}],
                }
            )
        )
        e = self._enricher(http, monkeypatch)
        ev = e._fetch(Indicator(IndicatorType.URL, "https://evil.test/"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.MALICIOUS
        assert "MALWARE" in ev.summary

    def test_empty_matches_returns_none(self, monkeypatch):
        # Safe Browsing returns ``{}`` (no `matches` key) for clean URLs.
        http = _FakeHttp(_FakeResp(json_body={}))
        e = self._enricher(http, monkeypatch)
        assert e._fetch(Indicator(IndicatorType.URL, "https://ok.test/")) is None


# ---------------------------------------------------------------------------
# PhishTank
# ---------------------------------------------------------------------------


class TestPhishTank:
    def _enricher(self, http, monkeypatch):
        monkeypatch.setenv("PHISHTANK_API_KEY", "fake")
        from avai.enrichers.sources.phishtank import PhishTankEnricher

        return PhishTankEnricher(http=http)

    def test_verified_phishing_yields_malicious(self, monkeypatch):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "results": {
                        "in_database": True,
                        "verified": True,
                        "valid": True,
                        "phish_id": 12345,
                    },
                }
            )
        )
        e = self._enricher(http, monkeypatch)
        ev = e._fetch(Indicator(IndicatorType.URL, "https://phish.test/"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.MALICIOUS
        assert "12345" in ev.summary

    def test_509_is_surfaced_as_rate_limited(self, monkeypatch):
        # Regression: PhishTank throttles with HTTP 509 (not 429), so the
        # shared client won't catch it; it must become a RateLimitedError
        # instead of a silent no-opinion that drops phishing hits.
        http = _FakeHttp(_FakeResp(status=509))
        e = self._enricher(http, monkeypatch)
        with pytest.raises(RateLimitedError):
            e._fetch(Indicator(IndicatorType.URL, "https://phish.test/"))

    def test_unverified_returns_none(self, monkeypatch):
        # In DB but not verified → don't yet rate as malicious.
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "results": {
                        "in_database": True,
                        "verified": False,
                        "valid": True,
                    },
                }
            )
        )
        e = self._enricher(http, monkeypatch)
        assert e._fetch(Indicator(IndicatorType.URL, "https://x/")) is None

    def test_not_in_database_returns_none(self, monkeypatch):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "results": {
                        "in_database": False,
                        "verified": False,
                        "valid": False,
                    },
                }
            )
        )
        e = self._enricher(http, monkeypatch)
        assert e._fetch(Indicator(IndicatorType.URL, "https://x/")) is None


# ---------------------------------------------------------------------------
# endoflife.date
# ---------------------------------------------------------------------------


class TestEndOfLife:
    def _enricher(self, http):
        from avai.enrichers.sources.endoflife import EndOfLifeEnricher

        return EndOfLifeEnricher(http=http)

    def test_past_eol_yields_suspicious(self):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "cycle": "12.04",
                    "eol": "2017-04-28",
                }
            )
        )
        e = self._enricher(http)
        ev = e._fetch(Indicator(IndicatorType.OS_VERSION, "ubuntu@12.04"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.SUSPICIOUS
        assert "2017-04-28" in ev.summary

    def test_future_eol_returns_none(self):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "cycle": "24.04",
                    "eol": "2099-04-28",
                }
            )
        )
        e = self._enricher(http)
        assert e._fetch(Indicator(IndicatorType.OS_VERSION, "ubuntu@24.04")) is None

    def test_bool_false_eol_returns_none(self):
        # endoflife.date returns `false` (bool) for not-yet-EOL releases.
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "cycle": "24.04",
                    "eol": False,
                }
            )
        )
        e = self._enricher(http)
        assert e._fetch(Indicator(IndicatorType.OS_VERSION, "ubuntu@24.04")) is None

    def test_bool_true_eol_yields_suspicious(self):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "cycle": "12.04",
                    "eol": True,
                }
            )
        )
        e = self._enricher(http)
        ev = e._fetch(Indicator(IndicatorType.OS_VERSION, "ubuntu@12.04"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.SUSPICIOUS

    def test_malformed_value_returns_none(self):
        # value missing the @version part — extractor never emits this,
        # but defensive at the source boundary.
        http = _FakeHttp(_FakeResp(json_body={}))
        e = self._enricher(http)
        assert e._fetch(Indicator(IndicatorType.OS_VERSION, "ubuntu")) is None


# ---------------------------------------------------------------------------
# crt.sh
# ---------------------------------------------------------------------------


class TestCrtSh:
    def _enricher(self, http):
        from avai.enrichers.sources.crtsh import CrtShEnricher

        return CrtShEnricher(http=http)

    def test_empty_entries_yields_suspicious(self):
        # A domain with no CT entries is unusual — flagged.
        http = _FakeHttp(_FakeResp(json_body=[]))
        e = self._enricher(http)
        ev = e._fetch(Indicator(IndicatorType.DOMAIN, "rare.test"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.SUSPICIOUS

    def test_existing_entries_yields_unknown_with_metadata(self):
        http = _FakeHttp(
            _FakeResp(
                json_body=[
                    {"not_before": "2020-01-01", "issuer_name": "Let's Encrypt"},
                    {"not_before": "2024-06-01", "issuer_name": "DigiCert"},
                ]
            )
        )
        e = self._enricher(http)
        ev = e._fetch(Indicator(IndicatorType.DOMAIN, "common.test"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.UNKNOWN
        assert "2020-01-01" in ev.summary

    def test_unparseable_json_returns_none(self):
        bad = _FakeResp(status=200)
        bad._json = None  # .json() will raise
        # Force the source to take the parse-failure path.
        e = self._enricher(_FakeHttp(bad))
        assert e._fetch(Indicator(IndicatorType.DOMAIN, "x.test")) is None
