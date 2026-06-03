"""Tests for the new collectors:

- process->flow attribution (ProcessConnectionResolver + NetworkFlowsCollector)
- DNS query capture (DnsQueriesCollector parser + DoH detection)
- ssh_authorized_keys / hosts_file / privilege_config parsers
- their indicator extractors
- the dashboard query functions that surface them.

Live capture / psutil are mocked so these run network- and root-free —
they pin the parsing + correlation + rendering logic that actually has
the bugs.
"""

from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from avai.dashboard import app, dns_queries, network_flows, persistence_tampering
from avai.enrichers import IndicatorType, extract_indicators
from avai.host_monitor import (
    DnsQueriesCollector,
    DnsQueryRow,
    HostsFileCollector,
    HostsFileRow,
    NetworkFlowRow,
    NetworkFlowsCollector,
    PrivilegeConfigCollector,
    PrivilegeConfigRow,
    ProcessConnectionResolver,
    Sink,
    SshAuthorizedKeyRow,
    SshAuthorizedKeysCollector,
    content_hash,
)
from avai.host_monitor.hosts.linux import LinuxPrivilegedAccounts

# ---------------------------------------------------------------------------
# process -> flow attribution
# ---------------------------------------------------------------------------


class _FakeResolver:
    def __init__(self, mapping):
        self._m = mapping

    def snapshot(self):
        return self._m


class TestProcessAttribution:
    def test_resolver_maps_remote_endpoint_to_process(self, monkeypatch):
        conns = [
            SimpleNamespace(raddr=SimpleNamespace(ip="8.8.8.8", port=443), pid=4321),
            SimpleNamespace(raddr=None, pid=999),  # listening — no remote, skipped
            SimpleNamespace(raddr=SimpleNamespace(ip="1.2.3.4", port=53), pid=None),
        ]
        monkeypatch.setattr(
            "avai.host_monitor.collectors.psutil.net_connections",
            lambda kind="inet": conns,
        )
        monkeypatch.setattr(
            "avai.host_monitor.collectors.psutil.Process",
            lambda pid: SimpleNamespace(name=lambda: "curl"),
        )
        snap = ProcessConnectionResolver().snapshot()
        assert snap[("8.8.8.8", 443)] == ("curl", 4321)
        assert ("1.2.3.4", 53) not in snap  # pid None skipped

    def test_collect_attaches_process_to_matching_flow(self, monkeypatch):
        sample = "(en6) IP 10.0.0.5.55555 > 8.8.8.8.443: tcp 0"
        c = NetworkFlowsCollector(
            resolver=_FakeResolver({("8.8.8.8", 443): ("curl", 4321)})
        )
        monkeypatch.setattr(c, "_capture", lambda: (sample, "en6"))
        rows = list(c.collect())
        assert len(rows) == 1
        assert rows[0]["process"] == "curl"
        assert rows[0]["pid"] == 4321

    def test_collect_sets_process_none_when_unresolved(self, monkeypatch):
        sample = "(en6) IP 10.0.0.5.55555 > 9.9.9.9.443: tcp 0"
        c = NetworkFlowsCollector(resolver=_FakeResolver({}))
        monkeypatch.setattr(c, "_capture", lambda: (sample, "en6"))
        row = list(c.collect())[0]
        # keys must be present (uniform-column insert) even when unresolved
        assert row["process"] is None and row["pid"] is None


# ---------------------------------------------------------------------------
# DNS query parsing + DoH detection
# ---------------------------------------------------------------------------


class TestDnsParse:
    def test_query_line(self):
        assert DnsQueriesCollector._parse_dns_line(
            "(en6) IP 10.0.0.5.51000 > 8.8.8.8.53: 1234+ A? example.com. (29)"
        ) == ("en6", "example.com", "A", "8.8.8.8")

    def test_aaaa_query_ipv6_resolver(self):
        out = DnsQueriesCollector._parse_dns_line(
            "(en6) IP6 fe80::1.51000 > 2001:4860:4860::8888.53: 5+ AAAA? host.test. (30)"
        )
        assert out == ("en6", "host.test", "AAAA", "2001:4860:4860::8888")

    def test_response_is_ignored(self):
        # src port 53 → a response, not a question
        assert (
            DnsQueriesCollector._parse_dns_line(
                "(en6) IP 8.8.8.8.53 > 10.0.0.5.51000: 1234 1/0/0 A 93.184.216.34 (45)"
            )
            is None
        )

    def test_non_dns_line_ignored(self):
        assert DnsQueriesCollector._parse_dns_line("ARP, Request who-has x") is None

    def test_aggregate_counts_repeats(self):
        out = (
            "(en6) IP 10.0.0.5.5.53 > 8.8.8.8.53: 1+ A? a.com. (20)\n"
            "(en6) IP 10.0.0.5.6.53 > 8.8.8.8.53: 2+ A? a.com. (20)\n"
        )
        agg = DnsQueriesCollector()._aggregate(out, "en6", {})
        assert agg[("a.com", "A", "8.8.8.8")]["count"] == 2

    def test_doh_endpoint_detected_from_connections(self, monkeypatch):
        c = DnsQueriesCollector(
            resolver=_FakeResolver({("1.1.1.1", 443): ("firefox", 22)})
        )
        monkeypatch.setattr(c, "_capture", lambda: ("", None))
        rows = list(c.collect())
        doh = [r for r in rows if r["qtype"] == "DoH"]
        assert len(doh) == 1
        assert doh[0]["qname"] == "Cloudflare"
        assert doh[0]["server_ip"] == "1.1.1.1"
        assert doh[0]["process"] == "firefox"


# ---------------------------------------------------------------------------
# ssh authorized_keys parser
# ---------------------------------------------------------------------------


_VALID_BLOB = base64.b64encode(b"raw-ed25519-public-key-bytes----").decode()


class TestAuthorizedKeys:
    def test_key_with_options_and_comment(self):
        rows = SshAuthorizedKeysCollector._parse_authorized_keys(
            'from="10.0.0.0/8",no-pty ssh-ed25519 ' f"{_VALID_BLOB} admin@laptop\n",
            "/Users/x/.ssh/authorized_keys",
            "x",
        )
        assert len(rows) == 1
        r = rows[0]
        assert r["key_type"] == "ssh-ed25519"
        assert r["options"] == 'from="10.0.0.0/8",no-pty'
        assert r["comment"] == "admin@laptop"
        assert r["fingerprint"].startswith("SHA256:")
        assert r["owner"] == "x"

    def test_plain_key_no_options(self):
        rows = SshAuthorizedKeysCollector._parse_authorized_keys(
            f"ssh-rsa {_VALID_BLOB} root\n", "/p", "root"
        )
        assert rows[0]["options"] is None
        assert rows[0]["key_type"] == "ssh-rsa"

    def test_comments_and_blanks_skipped(self):
        rows = SshAuthorizedKeysCollector._parse_authorized_keys(
            "# a comment\n\n   \n", "/p", "x"
        )
        assert rows == []

    def test_invalid_base64_yields_no_fingerprint(self):
        rows = SshAuthorizedKeysCollector._parse_authorized_keys(
            "ssh-ed25519 not!base64!! c\n", "/p", "x"
        )
        assert rows[0]["fingerprint"] is None


# ---------------------------------------------------------------------------
# /etc/hosts parser
# ---------------------------------------------------------------------------


class TestHostsParse:
    def test_parses_mappings_and_strips_comments(self):
        rows = HostsFileCollector._parse_hosts(
            "127.0.0.1 localhost\n# c\n6.6.6.6 my-bank.com extra # evil\n\n",
            "/etc/hosts",
        )
        assert [(r["ip"], r["hostnames"]) for r in rows] == [
            ("127.0.0.1", "localhost"),
            ("6.6.6.6", "my-bank.com extra"),
        ]

    def test_lone_ip_without_name_skipped(self):
        assert HostsFileCollector._parse_hosts("1.2.3.4\n", "/etc/hosts") == []


# ---------------------------------------------------------------------------
# privilege config parsers
# ---------------------------------------------------------------------------


class TestPrivilegeParsers:
    def test_sudoers_keeps_rules_drops_defaults(self):
        rows = PrivilegeConfigCollector._parse_sudoers(
            "Defaults env_reset\n"
            "# comment\n"
            "%admin ALL=(ALL) ALL\n"
            "bob ALL=(ALL) NOPASSWD: ALL\n",
            "/etc/sudoers",
        )
        assert [r["subject"] for r in rows] == ["%admin", "bob"]
        assert all(r["kind"] == "sudoers" for r in rows)

    def test_groups_only_privileged_with_members(self):
        rows = LinuxPrivilegedAccounts._parse_groups(
            "sudo:x:27:alice,bob\nwheel:x:10:\nstaff:x:50:carol\n",
            "/etc/group",
            LinuxPrivilegedAccounts._PRIV_GROUPS,
        )
        assert len(rows) == 1
        assert rows[0]["subject"] == "sudo"
        assert rows[0]["detail"] == "alice,bob"

    def test_passwd_flags_uid0_only(self):
        rows = LinuxPrivilegedAccounts._parse_passwd_uid0(
            "root:x:0:0:root:/root:/bin/bash\n"
            "backdoor:x:0:0::/:/bin/sh\n"
            "bob:x:1000:1000::/home/bob:/bin/bash\n",
            "/etc/passwd",
        )
        assert sorted(r["subject"] for r in rows) == ["backdoor", "root"]


# ---------------------------------------------------------------------------
# indicator extractors
# ---------------------------------------------------------------------------


class TestNewExtractors:
    def test_dns_query_emits_domain(self):
        out = extract_indicators("dns_queries", {"qname": "evil.example", "qtype": "A"})
        assert [(i.type, i.value) for i in out] == [
            (IndicatorType.DOMAIN, "evil.example")
        ]

    def test_doh_row_not_a_domain(self):
        # qname is a provider label, not a domain → no indicator
        assert (
            extract_indicators("dns_queries", {"qname": "Cloudflare", "qtype": "DoH"})
            == []
        )

    def test_hosts_emits_public_ip_and_domain(self):
        out = extract_indicators(
            "hosts_file", {"ip": "6.6.6.6", "hostnames": "my-bank.com localhost"}
        )
        pairs = {(i.type, i.value) for i in out}
        assert (IndicatorType.IPV4, "6.6.6.6") in pairs
        assert (IndicatorType.DOMAIN, "my-bank.com") in pairs

    def test_hosts_skips_loopback_ip(self):
        out = extract_indicators(
            "hosts_file", {"ip": "127.0.0.1", "hostnames": "localhost"}
        )
        assert out == []  # private ip + non-domain name


# ---------------------------------------------------------------------------
# dashboard query functions
# ---------------------------------------------------------------------------


@pytest.fixture
def db(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'n.db'}", connect_args={"check_same_thread": False}
    )
    sink = Sink(engine)
    sink.setup()
    run_id, ts = sink.start_run("h", 5)
    return engine, sink, run_id, ts


def _write(sink, model, rows, fields, ts, run_id):
    for r in rows:
        r["run_id"] = run_id
        r["collected_at"] = ts
        r["content_hash"] = content_hash(r, fields)
    sink.write(model, rows)


class TestDashboardDns:
    def test_dns_queries_summary_and_doh(self, db):
        engine, sink, run_id, ts = db
        _write(
            sink,
            DnsQueryRow,
            [
                {
                    "iface": "en6",
                    "qname": "good.com",
                    "qtype": "A",
                    "server_ip": "8.8.8.8",
                    "process": "curl",
                    "count": 3,
                    "first_seen": ts,
                    "last_seen": ts,
                },
                {
                    "iface": None,
                    "qname": "Cloudflare",
                    "qtype": "DoH",
                    "server_ip": "1.1.1.1",
                    "process": "firefox",
                    "count": 1,
                    "first_seen": ts,
                    "last_seen": ts,
                },
            ],
            ("qname", "qtype", "server_ip"),
            ts,
            run_id,
        )
        with Session(engine) as s:
            data = dns_queries(s, run_id)
        assert data["summary"]["domains"] == 2
        assert data["summary"]["queries"] == 4
        assert data["summary"]["doh"] == 1
        by_name = {r["qname"]: r["level"] for r in data["rows"]}
        assert by_name["good.com"] == "external DNS"  # public resolver
        assert by_name["Cloudflare"] == "DoH (encrypted)"

    def test_resolution_level_classification(self):
        from avai.dashboard import _dns_resolution_level

        assert _dns_resolution_level("192.168.1.1", "A") == "local resolver"
        assert _dns_resolution_level("127.0.0.1", "A") == "local resolver"
        assert _dns_resolution_level("8.8.8.8", "A") == "external DNS"
        assert _dns_resolution_level("1.1.1.1", "DoH") == "DoH (encrypted)"
        assert _dns_resolution_level(None, "A") == "unknown"
        assert _dns_resolution_level("not-an-ip", "A") == "unknown"

    def test_fragment_renders(self, db):
        engine, sink, run_id, ts = db
        _write(
            sink,
            DnsQueryRow,
            [
                {
                    "iface": "en6",
                    "qname": "tracker.bad",
                    "qtype": "A",
                    "server_ip": "8.8.8.8",
                    "process": "curl",
                    "count": 1,
                    "first_seen": ts,
                    "last_seen": ts,
                }
            ],
            ("qname", "qtype", "server_ip"),
            ts,
            run_id,
        )
        app.config.update(
            TESTING=True, DB_PATH=str(engine.url).replace("sqlite:///", "")
        )
        with app.test_client() as c:
            html = c.get("/fragments/dns-queries").data.decode()
        assert "tracker.bad" in html and "DNS queries" in html


class TestDashboardPersistence:
    def test_sections_populated(self, db):
        engine, sink, run_id, ts = db
        _write(
            sink,
            SshAuthorizedKeyRow,
            [
                {
                    "path": "/Users/x/.ssh/authorized_keys",
                    "owner": "x",
                    "key_type": "ssh-ed25519",
                    "fingerprint": "SHA256:abc",
                    "comment": "admin@host",
                    "options": None,
                }
            ],
            ("path", "owner", "key_type", "fingerprint"),
            ts,
            run_id,
        )
        _write(
            sink,
            HostsFileRow,
            [
                {
                    "source_path": "/etc/hosts",
                    "ip": "6.6.6.6",
                    "hostnames": "my-bank.com",
                }
            ],
            ("ip", "hostnames"),
            ts,
            run_id,
        )
        _write(
            sink,
            PrivilegeConfigRow,
            [
                {
                    "kind": "sudoers",
                    "subject": "bob",
                    "detail": "bob ALL=(ALL) NOPASSWD: ALL",
                    "source_path": "/etc/sudoers",
                }
            ],
            ("kind", "subject", "detail"),
            ts,
            run_id,
        )
        with Session(engine) as s:
            data = persistence_tampering(s, run_id)
        assert data["any"] is True
        assert data["counts"]["ssh_keys"]["total"] == 1
        assert data["ssh_keys"][0]["owner"] == "x"
        assert data["hosts"][0]["ip"] == "6.6.6.6"
        assert data["privilege"][0]["subject"] == "bob"

    def test_fragment_renders(self, db):
        engine, sink, run_id, ts = db
        _write(
            sink,
            HostsFileRow,
            [
                {
                    "source_path": "/etc/hosts",
                    "ip": "6.6.6.6",
                    "hostnames": "my-bank.com",
                }
            ],
            ("ip", "hostnames"),
            ts,
            run_id,
        )
        app.config.update(
            TESTING=True, DB_PATH=str(engine.url).replace("sqlite:///", "")
        )
        with app.test_client() as c:
            html = c.get("/fragments/persistence").data.decode()
        assert "my-bank.com" in html and "persistence" in html.lower()

    def test_empty_when_no_data(self, db):
        engine, sink, run_id, ts = db
        with Session(engine) as s:
            data = persistence_tampering(s, run_id)
        assert data["any"] is False


class TestNetworkFlowProcessColumn:
    def test_process_attached_in_dashboard(self, db):
        engine, sink, run_id, ts = db
        _write(
            sink,
            NetworkFlowRow,
            [
                {
                    "iface": "en6",
                    "proto": "tcp",
                    "dst_ip": "8.8.8.8",
                    "dst_port": 443,
                    "service": "https",
                    "packets": 10,
                    "process": "curl",
                    "pid": 4321,
                    "first_seen": ts,
                    "last_seen": ts,
                }
            ],
            ("iface", "proto", "dst_ip", "dst_port"),
            ts,
            run_id,
        )
        with Session(engine) as s:
            rows = network_flows(s, run_id)["rows"]
        assert rows[0]["process"] == "curl"
