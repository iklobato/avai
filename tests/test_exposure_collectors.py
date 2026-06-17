"""Tier 2 exposure-collector parsers, enrichment, and wiring.

macOS samples are real output from this platform; Linux/Windows samples
are representative of the documented formats.
"""

from __future__ import annotations

from avai.enrichers import IndicatorType, extract_indicators
from avai.host_monitor.exposure_collectors import (
    LinuxPromiscParser,
    LinuxProxyEnvParser,
    LinuxTrustListParser,
    MacosCertParser,
    MacosMountSharesParser,
    MacosPromiscParser,
    MacosProxyParser,
    ProcMountsSharesParser,
    WhoParser,
    WindowsCertParser,
    WindowsProxyParser,
    WindowsSharesParser,
)
from avai.host_monitor.hosts.linux import LinuxHost
from avai.host_monitor.hosts.macos import MacOSHost
from avai.host_monitor.hosts.windows import WindowsHost
from avai.host_monitor.prompts import Prompts

_P = Prompts(system="", user_template="")


class TestMacosProxyParser:
    def test_all_disabled_yields_nothing(self):
        text = "<dictionary> {\n  HTTPEnable : 0\n  HTTPSEnable : 0\n}"
        assert MacosProxyParser().parse(text) == []

    def test_enabled_http_and_pac(self):
        text = (
            "  HTTPEnable : 1\n  HTTPProxy : 10.0.0.9\n  HTTPPort : 8080\n"
            "  ProxyAutoConfigEnable : 1\n"
            "  ProxyAutoConfigURLString : http://evil/proxy.pac\n"
        )
        rows = MacosProxyParser().parse(text)
        by = {r["scope"]: r for r in rows}
        assert by["http"]["host"] == "10.0.0.9" and by["http"]["port"] == "8080"
        assert by["pac"]["pac_url"] == "http://evil/proxy.pac"


class TestWhoParser:
    def test_local_and_remote(self):
        text = "iklo console May 31 17:50\nbob pts/0 2026-06-05 14:43 (203.0.113.7)\n"
        rows = WhoParser().parse(text)
        assert rows[0]["source"] == "local"
        assert rows[0]["user"] == "iklo"
        assert rows[1]["source"] == "203.0.113.7"
        assert rows[1]["tty"] == "pts/0"


class TestSharesParsers:
    def test_macos_keeps_only_network_fs(self):
        text = (
            "/dev/disk1s5s1 on / (apfs, sealed, local)\n"
            "//bob@nas.lan/media on /Volumes/media (smbfs, nodev, nosuid)\n"
        )
        rows = MacosMountSharesParser().parse(text)
        assert len(rows) == 1
        assert rows[0]["remote"] == "//bob@nas.lan/media"
        assert rows[0]["fstype"] == "smbfs"

    def test_proc_mounts_keeps_only_network_fs(self):
        text = (
            "/dev/sda1 / ext4 rw,relatime 0 0\n"
            "//nas/share /mnt/share cifs rw,vers=3.0 0 0\n"
        )
        rows = ProcMountsSharesParser().parse(text)
        assert [r["fstype"] for r in rows] == ["cifs"]
        assert rows[0]["remote"] == "//nas/share"


class TestPromiscParsers:
    def test_macos_flags(self):
        text = (
            "en6: flags=8863<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500\n"
            "\tinet 192.168.1.50 netmask 0xffffff00\n"
            "en7: flags=8943<UP,PROMISC,RUNNING> mtu 1500\n"
        )
        rows = MacosPromiscParser().parse(text)
        by = {r["interface"]: r for r in rows}
        assert by["en6"]["promiscuous"] == 0
        assert by["en7"]["promiscuous"] == 1

    def test_linux_ip_link(self):
        text = (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
            "2: eth0: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500\n"
        )
        rows = LinuxPromiscParser().parse(text)
        by = {r["interface"]: r for r in rows}
        assert by["lo"]["promiscuous"] == 0
        assert by["eth0"]["promiscuous"] == 1


class TestCertParsers:
    def test_macos_pairs_hash_and_label(self):
        text = (
            "SHA-256 hash: ABC123\n"
            '    "alis"<blob>="Go Daddy Root"\n'
            '    "labl"<blob>="Go Daddy Root"\n'
        )
        rows = MacosCertParser().parse(text)
        assert rows == [
            {
                "subject": "Go Daddy Root",
                "fingerprint": "ABC123",
                "source": "System.keychain",
                "raw_json": rows[0]["raw_json"],
            }
        ]

    def test_linux_trust_list_labels(self):
        text = "pkcs11:id=x;type=cert\n    type: certificate\n    label: GlobalSign\n"
        rows = LinuxTrustListParser().parse(text)
        assert rows[0]["subject"] == "GlobalSign"

    def test_windows_cert_json(self):
        text = '[{"Subject":"CN=Evil","Thumbprint":"DEAD"}]'
        rows = WindowsCertParser().parse(text)
        assert rows[0]["subject"] == "CN=Evil"
        assert rows[0]["fingerprint"] == "DEAD"


class TestLinuxProxyEnv:
    def test_reads_proxy_vars(self):
        text = '# env\nhttp_proxy="http://10.0.0.9:3128"\nLANG=en_US.UTF-8\n'
        rows = LinuxProxyEnvParser().parse(text)
        assert len(rows) == 1
        assert rows[0]["scope"] == "http"
        assert "10.0.0.9" in rows[0]["host"]


class TestWindowsParsers:
    def test_proxy_enabled(self):
        text = '{"ProxyEnable":1,"ProxyServer":"10.0.0.9:8080","AutoConfigURL":null}'
        rows = WindowsProxyParser().parse(text)
        assert rows[0]["host"] == "10.0.0.9" and rows[0]["port"] == "8080"

    def test_shares(self):
        text = '[{"ServerName":"nas","ShareName":"data","Dialect":"3.1.1"}]'
        rows = WindowsSharesParser().parse(text)
        assert rows[0]["remote"] == "\\\\nas\\data"


class TestEnrichment:
    def test_proxy_public_host_enriched(self):
        inds = extract_indicators("proxy_config", {"host": "8.8.8.8"})
        assert inds and inds[0].type == IndicatorType.IPV4

    def test_proxy_private_host_not_enriched(self):
        assert extract_indicators("proxy_config", {"host": "10.0.0.9"}) == []

    def test_share_server_extracted(self):
        inds = extract_indicators("network_shares", {"remote": "//files.evil.com/x"})
        assert inds and inds[0].type == IndicatorType.DOMAIN
        assert inds[0].value == "files.evil.com"

    def test_login_remote_ip_enriched(self):
        inds = extract_indicators("login_sessions", {"source": "9.9.9.9"})
        assert inds and inds[0].type == IndicatorType.IPV4

    def test_login_local_not_enriched(self):
        assert extract_indicators("login_sessions", {"source": "local"}) == []


class TestWiring:
    def test_macos_and_linux_assemble_all_five(self):
        want = {
            "proxy_config",
            "login_sessions",
            "network_shares",
            "promiscuous_ifaces",
            "trusted_roots",
        }
        for host in (MacOSHost(), LinuxHost()):
            names = {c.name for c in host.snapshot_collectors(_P)}
            assert want <= names

    def test_windows_composes_out_promiscuous(self):
        names = {c.name for c in WindowsHost().snapshot_collectors(_P)}
        assert {"proxy_config", "trusted_roots", "network_shares"} <= names
        assert "promiscuous_ifaces" not in names
