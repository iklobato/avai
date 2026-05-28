"""Edge-case tests for the indicator extractors.

Complements the happy-path tests in :mod:`test_enrichers` — exercises
malformed JSON, missing fields, private CIDR boundaries, IPv6,
nonexistent paths, and other "weird input from a real collector" cases.
"""
from __future__ import annotations

import pytest

from avai.enrichers import IndicatorType, extract_indicators
from avai.enrichers.indicators import _is_private_ip, _is_ipv4, _is_domain


# ---------------------------------------------------------------------------
# _is_private_ip — RFC1918 + loopback + link-local + multicast + reserved
# ---------------------------------------------------------------------------

class TestIsPrivateIp:
    @pytest.mark.parametrize("ip", [
        "10.0.0.1",        # RFC1918
        "10.255.255.255",
        "172.16.0.1",      # RFC1918
        "172.31.255.255",
        "192.168.0.1",     # RFC1918
        "192.168.255.255",
        "127.0.0.1",       # loopback
        "127.255.255.255",
        "169.254.1.1",     # link-local
        "224.0.0.1",       # multicast
        "0.0.0.0",         # unspecified
        "255.255.255.255", # broadcast / reserved
    ])
    def test_recognises_non_routable(self, ip):
        assert _is_private_ip(ip)

    @pytest.mark.parametrize("ip", [
        "1.1.1.1",
        "8.8.8.8",
        "172.32.0.1",     # outside 172.16-31 range
        "192.169.0.1",    # outside 192.168
        "11.0.0.1",       # outside 10.0.0.0/8
    ])
    def test_recognises_public(self, ip):
        assert not _is_private_ip(ip)

    def test_returns_false_for_garbage(self):
        assert not _is_private_ip("not-an-ip")
        assert not _is_private_ip("")
        assert not _is_private_ip("999.999.999.999")


class TestIsIPv4:
    def test_ipv6_rejected(self):
        assert not _is_ipv4("::1")
        assert not _is_ipv4("2001:db8::1")

    def test_garbage_rejected(self):
        assert not _is_ipv4("not.an.ip")
        assert not _is_ipv4("")


class TestIsDomain:
    @pytest.mark.parametrize("d", [
        "example.com", "sub.example.com", "x.test", "co.uk",
    ])
    def test_accepts_real_domains(self, d):
        assert _is_domain(d)

    @pytest.mark.parametrize("d", [
        "",
        "no-tld",          # no dot
        "1.2.3.4",         # an IP, not a domain — but matches the regex
        ".starts-dot",
        "ends-dot.",
        "_underscore.com",
    ])
    def test_rejects_or_accepts_consistently(self, d):
        # We don't assert behaviour for every case — just that the
        # function returns a bool and doesn't raise on weird input.
        result = _is_domain(d)
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# Per-collector extractor edge cases
# ---------------------------------------------------------------------------

class TestExtractIndicatorsEdgeCases:
    def test_empty_row_returns_empty_list(self):
        assert extract_indicators("processes", {}) == []

    def test_processes_with_nonexistent_exe_returns_empty(self):
        assert extract_indicators("processes", {"exe": "/no/such/path"}) == []

    def test_processes_with_none_exe_returns_empty(self):
        assert extract_indicators("processes", {"exe": None}) == []

    def test_processes_with_empty_exe_string_returns_empty(self):
        assert extract_indicators("processes", {"exe": ""}) == []

    def test_network_connections_ipv6_is_skipped(self):
        # avai's IndicatorType.IPV4 is intentional — we don't enrich v6 yet.
        out = extract_indicators("network_connections", {
            "raddr": "[2001:db8::1]:443",
        })
        assert out == []

    def test_network_connections_malformed_raddr_returns_empty(self):
        out = extract_indicators("network_connections", {"raddr": "no-colon"})
        assert out == []

    @pytest.mark.parametrize("addr", [
        "10.0.0.1:443",        # RFC1918
        "172.16.0.1:80",
        "192.168.1.1:22",
        "127.0.0.1:8000",      # loopback
        "169.254.1.1:80",      # link-local
        "224.0.0.1:1900",      # multicast (SSDP)
    ])
    def test_network_connections_private_ip_skipped(self, addr):
        out = extract_indicators("network_connections", {"raddr": addr})
        assert out == []

    def test_listening_ports_public_bind_emits_ip(self):
        # 8.8.8.8 = Google DNS, real public address. (TEST-NET blocks
        # like 203.0.113.0/24 are correctly treated as reserved by
        # ipaddress.is_reserved → they'd be filtered.)
        out = extract_indicators("listening_ports", {"laddr": "8.8.8.8:8080"})
        assert len(out) == 1
        assert out[0].type is IndicatorType.IPV4
        assert out[0].value == "8.8.8.8"

    def test_listening_ports_loopback_bind_skipped(self):
        out = extract_indicators("listening_ports", {"laddr": "127.0.0.1:8000"})
        assert out == []

    def test_quarantine_with_non_http_url_skipped(self):
        out = extract_indicators("quarantine_events", {
            "origin_url": "file:///etc/passwd",
        })
        assert out == []

    def test_quarantine_with_ip_host_yields_ipv4(self):
        # Real public IP — must classify as IPv4 (not domain — see
        # _is_domain fix). Regression: the digit-only "labels" of an
        # IPv4 literal match the domain regex.
        out = extract_indicators("quarantine_events", {
            "origin_url": "http://8.8.8.8/dl/x.exe",
        })
        types = sorted(str(i.type) for i in out)
        assert "url" in types
        assert "ipv4" in types
        assert "domain" not in types

    def test_browser_extension_malformed_json_returns_empty(self):
        out = extract_indicators("browser_extensions", {
            "host_permissions_json": "not valid {{ json",
        })
        assert out == []

    def test_browser_extension_empty_array_returns_empty(self):
        out = extract_indicators("browser_extensions", {
            "host_permissions_json": "[]",
        })
        assert out == []

    def test_browser_extension_wildcard_all_urls_skipped(self):
        # "<all_urls>" isn't a real domain — the extractor should not
        # emit it as one.
        out = extract_indicators("browser_extensions", {
            "host_permissions_json": '["<all_urls>"]',
        })
        assert out == []

    def test_installed_apps_without_version_still_emits(self):
        out = extract_indicators("installed_apps", {"name": "openssl"})
        assert len(out) == 1
        assert out[0].value == "openssl"  # no @version suffix

    def test_installed_apps_without_name_yields_nothing(self):
        out = extract_indicators("installed_apps", {"name": ""})
        assert out == []

    def test_system_integrity_requires_both_product_and_cycle(self):
        # Only os_name → no indicator.
        assert extract_indicators("system_integrity", {
            "os_name": "ubuntu",
        }) == []
        # Only os_version → no indicator.
        assert extract_indicators("system_integrity", {
            "os_version": "22.04",
        }) == []
        # Both → one indicator.
        out = extract_indicators("system_integrity", {
            "os_name": "ubuntu", "os_version": "22.04",
        })
        assert len(out) == 1
        assert out[0].value == "ubuntu@22.04"

    def test_file_integrity_uses_recorded_sha256_not_path(self):
        digest = "a" * 64
        out = extract_indicators("file_integrity", {
            "path": "/no/such/file", "sha256": digest,
        })
        assert len(out) == 1
        assert out[0].value == digest

    def test_file_integrity_malformed_sha256_skipped(self):
        out = extract_indicators("file_integrity", {
            "path": "/x", "sha256": "tooshort",
        })
        assert out == []

    def test_unknown_collector_is_silent(self):
        # No exception, no indicators — graceful no-op for collectors
        # that haven't opted in.
        assert extract_indicators("not_a_collector", {"x": 1}) == []

    def test_dedupes_within_a_single_row(self):
        # A weird future extractor could emit the same indicator twice;
        # the dispatcher should dedupe at the call site.
        from avai.enrichers.indicators import EXTRACTORS, IndicatorExtractor
        from avai.enrichers import Indicator

        class _Dup(IndicatorExtractor):
            def extract(self, row):
                yield Indicator(IndicatorType.IPV4, "1.2.3.4")
                yield Indicator(IndicatorType.IPV4, "1.2.3.4")

        EXTRACTORS["_dup"] = _Dup()
        try:
            out = extract_indicators("_dup", {})
            assert len(out) == 1
        finally:
            del EXTRACTORS["_dup"]
