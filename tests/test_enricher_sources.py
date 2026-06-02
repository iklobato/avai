"""Mocked-HTTP tests for the concrete enricher sources.

The framework tests in :mod:`test_enrichers` cover dispatch, caching,
and the ABC contract. These tests pin each source's *response-parsing
behaviour* — given a stubbed HTTP response, does the source return
the expected ``Evidence``?  Run network-free by replacing the source's
HTTP client with a fake.
"""

from __future__ import annotations

import json
from typing import Any

from avai.enrichers.base import Indicator, IndicatorType, VerdictHint

# ---------------------------------------------------------------------------
# Fake HTTP client — mimics requests.Response just enough for the
# narrow API surface the enrichers use.
# ---------------------------------------------------------------------------


class _FakeResp:
    def __init__(self, status: int = 200, json_body: Any = None, text: str = ""):
        self.status_code = status
        self._json = json_body
        self.text = text or (json.dumps(json_body) if json_body is not None else "")
        self.headers: dict[str, str] = {}

    def json(self):
        if self._json is None:
            raise ValueError("no json body configured")
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeHttp:
    """Records every call; returns canned responses keyed by URL prefix
    or in FIFO order."""

    def __init__(self, response: _FakeResp = None, responses: list[_FakeResp] = None):
        self._fixed = response
        self._queue = list(responses or [])
        self.calls: list[tuple[str, str, dict]] = []

    def _next(self):
        if self._queue:
            return self._queue.pop(0)
        if self._fixed is not None:
            return self._fixed
        raise AssertionError("FakeHttp ran out of canned responses")

    def get(self, url, **kw):
        self.calls.append(("GET", url, kw))
        return self._next()

    def post(self, url, **kw):
        self.calls.append(("POST", url, kw))
        return self._next()

    def set_rate(self, host, rate):  # noqa: D401
        pass


# ---------------------------------------------------------------------------
# MalwareBazaar
# ---------------------------------------------------------------------------


class TestMalwareBazaar:
    def _enricher(self, http):
        from avai.enrichers.sources.malware_bazaar import MalwareBazaarEnricher

        return MalwareBazaarEnricher(http=http)

    def test_hit_returns_malicious_verdict(self, monkeypatch):
        monkeypatch.setenv("ABUSE_CH_AUTH_KEY", "fake")
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "query_status": "ok",
                    "data": [
                        {
                            "signature": "AsyncRAT",
                            "file_type": "exe",
                            "first_seen": "2024-01-01",
                            "last_seen": "2024-06-30",
                            "tags": ["RAT", "AsyncRAT"],
                        }
                    ],
                }
            )
        )
        e = self._enricher(http)
        ev = e._fetch(Indicator(IndicatorType.SHA256, "a" * 64))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.MALICIOUS
        assert ev.confidence > 0.9
        assert "AsyncRAT" in ev.summary

    def test_no_results_returns_none(self, monkeypatch):
        monkeypatch.setenv("ABUSE_CH_AUTH_KEY", "fake")
        http = _FakeHttp(_FakeResp(json_body={"query_status": "no_results"}))
        e = self._enricher(http)
        assert e._fetch(Indicator(IndicatorType.SHA256, "a" * 64)) is None

    def test_unauthorized_returns_none(self, monkeypatch):
        monkeypatch.setenv("ABUSE_CH_AUTH_KEY", "fake")
        http = _FakeHttp(_FakeResp(status=401, text="Unauthorized"))
        e = self._enricher(http)
        assert e._fetch(Indicator(IndicatorType.SHA256, "a" * 64)) is None


# ---------------------------------------------------------------------------
# CIRCL hashlookup — whitelist signal
# ---------------------------------------------------------------------------


class TestCirclHashlookup:
    def _enricher(self, http):
        from avai.enrichers.sources.circl_hashlookup import CirclHashlookupEnricher

        return CirclHashlookupEnricher(http=http)

    def test_hit_returns_benign(self):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "ProductName": "Windows 10 Notepad",
                    "FileName": "notepad.exe",
                    "FileSize": "12345",
                }
            )
        )
        e = self._enricher(http)
        ev = e._fetch(Indicator(IndicatorType.SHA1, "a" * 40))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.BENIGN
        assert "Notepad" in ev.summary

    def test_not_found_returns_none(self):
        http = _FakeHttp(_FakeResp(status=404))
        e = self._enricher(http)
        assert e._fetch(Indicator(IndicatorType.SHA1, "a" * 40)) is None

    def test_known_malicious_hit_is_not_reported_benign(self):
        # Regression: CIRCL aggregates known-malicious hashes alongside
        # the NSRL known-good set. A KnownMalicious hit used to be emitted
        # as a BENIGN whitelist hit (conf 0.9), which could suppress the
        # judge on a known-bad binary.
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "FileName": "evil.exe",
                    "KnownMalicious": True,
                }
            )
        )
        e = self._enricher(http)
        ev = e._fetch(Indicator(IndicatorType.SHA1, "b" * 40))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.MALICIOUS
        assert ev.verdict_hint is not VerdictHint.BENIGN


# ---------------------------------------------------------------------------
# Shodan InternetDB
# ---------------------------------------------------------------------------


class TestShodanInternetDB:
    def _enricher(self, http):
        from avai.enrichers.sources.shodan_internetdb import ShodanInternetDBEnricher

        return ShodanInternetDBEnricher(http=http)

    def test_cve_hit_yields_suspicious(self):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "ports": [22, 80],
                    "vulns": ["CVE-2024-12345"],
                    "tags": [],
                    "hostnames": ["x.example"],
                }
            )
        )
        e = self._enricher(http)
        ev = e._fetch(Indicator(IndicatorType.IPV4, "1.2.3.4"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.SUSPICIOUS

    def test_honeypot_tag_yields_suspicious(self):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "ports": [22],
                    "vulns": [],
                    "tags": ["honeypot"],
                    "hostnames": [],
                }
            )
        )
        e = self._enricher(http)
        ev = e._fetch(Indicator(IndicatorType.IPV4, "1.2.3.4"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.SUSPICIOUS

    def test_clean_host_yields_unknown(self):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "ports": [443],
                    "vulns": [],
                    "tags": [],
                    "hostnames": ["safe.test"],
                }
            )
        )
        e = self._enricher(http)
        ev = e._fetch(Indicator(IndicatorType.IPV4, "1.2.3.4"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.UNKNOWN

    def test_404_returns_none(self):
        http = _FakeHttp(_FakeResp(status=404))
        e = self._enricher(http)
        assert e._fetch(Indicator(IndicatorType.IPV4, "1.2.3.4")) is None


# ---------------------------------------------------------------------------
# ipwho.is geolocation — informational, never a threat verdict
# ---------------------------------------------------------------------------


class TestIpwhoisGeo:
    def _enricher(self, http):
        from avai.enrichers.sources.ipwhois_geo import IpwhoisGeoEnricher

        return IpwhoisGeoEnricher(http=http)

    def test_success_returns_geo_details_and_unknown_hint(self):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "success": True,
                    "country": "United States",
                    "country_code": "US",
                    "region": "California",
                    "city": "Mountain View",
                    "latitude": 37.4,
                    "longitude": -122.0,
                    "connection": {"asn": 15169, "org": "Google LLC", "isp": "Google"},
                }
            )
        )
        e = self._enricher(http)
        ev = e._fetch(Indicator(IndicatorType.IPV4, "8.8.8.8"))
        assert ev is not None
        # purely informational — must not raise a threat verdict
        assert ev.verdict_hint is VerdictHint.UNKNOWN
        assert ev.confidence == 0.0
        assert ev.details["city"] == "Mountain View"
        assert ev.details["country"] == "United States"
        assert ev.details["asn"] == 15169
        assert ev.details["org"] == "Google LLC"
        assert "Mountain View" in ev.summary and "AS15169" in ev.summary

    def test_unsuccessful_body_returns_none(self):
        # bogon / reserved address → ipwho.is answers success=false
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "success": False,
                    "message": "Reserved range",
                }
            )
        )
        e = self._enricher(http)
        assert e._fetch(Indicator(IndicatorType.IPV4, "10.0.0.1")) is None

    def test_non_200_returns_none(self):
        http = _FakeHttp(_FakeResp(status=503))
        e = self._enricher(http)
        assert e._fetch(Indicator(IndicatorType.IPV4, "8.8.8.8")) is None

    def test_ipv6_indicator_supported_and_parsed(self):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "success": True,
                    "type": "IPv6",
                    "country": "United States",
                    "country_code": "US",
                    "region": "California",
                    "city": "San Francisco",
                    "connection": {"asn": 13335, "org": "Cloudflare, Inc."},
                }
            )
        )
        e = self._enricher(http)
        ind = Indicator(IndicatorType.IPV6, "2606:4700:4700::1111")
        assert e.supports(ind)
        ev = e._fetch(ind)
        assert ev is not None
        assert ev.details["city"] == "San Francisco"
        assert ev.details["asn"] == 13335
        # the v6 literal was used directly in the request URL
        assert any("2606:4700:4700::1111" in url for _, url, _ in http.calls)


# ---------------------------------------------------------------------------
# CISA KEV — uses a cached feed not a per-IOC API
# ---------------------------------------------------------------------------


class TestCisaKev:
    def _enricher(self, http):
        from avai.enrichers.sources.cisa_kev import CisaKevEnricher

        # Reset class-level cache so tests don't bleed into each other.
        CisaKevEnricher._catalog = {}
        CisaKevEnricher._catalog_ts = 0.0
        return CisaKevEnricher(http=http)

    def test_known_exploited_cve_returns_malicious(self):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2024-99999",
                            "vendorProject": "ACME",
                            "product": "WidgetServer",
                            "vulnerabilityName": "RCE in widget",
                            "dateAdded": "2024-12-01",
                            "shortDescription": "remote code execution",
                            "knownRansomwareCampaignUse": "Known",
                        }
                    ],
                }
            )
        )
        e = self._enricher(http)
        ev = e._fetch(Indicator(IndicatorType.CVE, "CVE-2024-99999"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.MALICIOUS
        assert "WidgetServer" in ev.summary

    def test_cve_not_in_catalog_returns_none(self):
        http = _FakeHttp(_FakeResp(json_body={"vulnerabilities": []}))
        e = self._enricher(http)
        assert e._fetch(Indicator(IndicatorType.CVE, "CVE-1999-0000")) is None


# ---------------------------------------------------------------------------
# OSV.dev
# ---------------------------------------------------------------------------


class TestOSV:
    def _enricher(self, http):
        from avai.enrichers.sources.osv import OSVEnricher

        return OSVEnricher(http=http)

    def test_package_with_advisory_returns_suspicious(self):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "vulns": [
                        {"id": "GHSA-1234-aaaa-bbbb", "summary": "buffer overflow"},
                    ],
                }
            )
        )
        e = self._enricher(http)
        ev = e._fetch(Indicator(IndicatorType.PACKAGE, "openssl@1.0.0"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.SUSPICIOUS
        assert "GHSA-1234-aaaa-bbbb" in ev.summary

    def test_clean_package_returns_none(self):
        http = _FakeHttp(_FakeResp(json_body={"vulns": []}))
        e = self._enricher(http)
        assert e._fetch(Indicator(IndicatorType.PACKAGE, "ok@1.0")) is None

    def test_cve_indicator_uses_id_query(self):
        http = _FakeHttp(
            _FakeResp(json_body={"vulns": [{"id": "CVE-2024-1", "summary": "x"}]})
        )
        e = self._enricher(http)
        ev = e._fetch(Indicator(IndicatorType.CVE, "CVE-2024-1"))
        assert ev is not None

    def test_cve_alias_is_surfaced_for_forward_chain(self):
        # Regression: OSV's primary id is often GHSA-/PYSEC-, with the CVE
        # only in aliases. details["vuln_ids"] used to carry the primary id
        # only, so the chain's CVE forward-enrichment (NVD CVSS, CISA KEV)
        # never fired. Aliases must be surfaced too.
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "vulns": [
                        {
                            "id": "GHSA-1234-aaaa-bbbb",
                            "aliases": ["CVE-2024-9999"],
                            "summary": "rce",
                        },
                    ],
                }
            )
        )
        e = self._enricher(http)
        ev = e._fetch(Indicator(IndicatorType.PACKAGE, "pkg@1.0"))
        assert ev is not None
        vuln_ids = ev.details["vuln_ids"]
        assert "CVE-2024-9999" in vuln_ids  # alias surfaced
        assert "GHSA-1234-aaaa-bbbb" in vuln_ids  # primary id kept


# ---------------------------------------------------------------------------
# VirusTotal — verdict heuristic
# ---------------------------------------------------------------------------


class TestVirusTotal:
    def _enricher(self, http, monkeypatch):
        monkeypatch.setenv("VT_API_KEY", "fake")
        from avai.enrichers.sources.virustotal import VirusTotalEnricher

        return VirusTotalEnricher(http=http)

    def _vt_body(self, *, malicious=0, suspicious=0, harmless=0, undetected=0):
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "undetected": undetected,
                    }
                }
            }
        }

    def test_many_malicious_engines_yields_malicious(self, monkeypatch):
        http = _FakeHttp(
            _FakeResp(json_body=self._vt_body(malicious=30, harmless=20, undetected=15))
        )
        e = self._enricher(http, monkeypatch)
        ev = e._fetch(Indicator(IndicatorType.SHA256, "a" * 64))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.MALICIOUS

    def test_few_malicious_engines_yields_suspicious(self, monkeypatch):
        http = _FakeHttp(
            _FakeResp(json_body=self._vt_body(malicious=2, harmless=50, undetected=20))
        )
        e = self._enricher(http, monkeypatch)
        ev = e._fetch(Indicator(IndicatorType.SHA256, "a" * 64))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.SUSPICIOUS

    def test_zero_malicious_with_many_engines_yields_benign(self, monkeypatch):
        http = _FakeHttp(
            _FakeResp(
                json_body=self._vt_body(
                    malicious=0, suspicious=0, harmless=60, undetected=10
                )
            )
        )
        e = self._enricher(http, monkeypatch)
        ev = e._fetch(Indicator(IndicatorType.SHA256, "a" * 64))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.BENIGN

    def test_404_returns_none(self, monkeypatch):
        http = _FakeHttp(_FakeResp(status=404))
        e = self._enricher(http, monkeypatch)
        assert e._fetch(Indicator(IndicatorType.SHA256, "a" * 64)) is None


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------


class TestAbuseIpDb:
    def _enricher(self, http, monkeypatch):
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake")
        from avai.enrichers.sources.abuseipdb import AbuseIpDbEnricher

        return AbuseIpDbEnricher(http=http)

    def test_high_score_yields_malicious(self, monkeypatch):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "data": {
                        "abuseConfidenceScore": 90,
                        "totalReports": 50,
                        "countryCode": "??",
                        "isp": "Bad ISP",
                    }
                }
            )
        )
        e = self._enricher(http, monkeypatch)
        ev = e._fetch(Indicator(IndicatorType.IPV4, "1.2.3.4"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.MALICIOUS

    def test_low_score_yields_unknown(self, monkeypatch):
        http = _FakeHttp(
            _FakeResp(
                json_body={
                    "data": {
                        "abuseConfidenceScore": 0,
                        "totalReports": 0,
                    }
                }
            )
        )
        e = self._enricher(http, monkeypatch)
        ev = e._fetch(Indicator(IndicatorType.IPV4, "1.2.3.4"))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.UNKNOWN
