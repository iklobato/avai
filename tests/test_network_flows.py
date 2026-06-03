"""Tests for the tcpdump flow aggregator collector + its dashboard table.

Live capture needs root, so these feed canned ``tcpdump -t -q`` output
through the parser/aggregator (the part with the bugs), test indicator
extraction, and render the dashboard table from seeded rows — including
the by-destination aggregation, the interface column, and graceful
behaviour when the network_flows table doesn't exist yet.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from avai.dashboard import app, network_flows
from avai.enrichers import IndicatorType, extract_indicators
from avai.host_monitor import NetworkFlowRow, NetworkFlowsCollector, Sink

# macOS/default form (no interface prefix), -t (no timestamp)
SAMPLE_MACOS = """\
IP 10.0.0.5.54321 > 142.250.80.46.443: tcp 0
IP 10.0.0.5.54322 > 142.250.80.46.443: tcp 52
IP 10.0.0.5.5353 > 224.0.0.251.5353: UDP, length 45
ARP, Request who-has 10.0.0.1 tell 10.0.0.5, length 28
IP 10.0.0.5.51000 > 8.8.8.8.53: UDP, length 30

"""

# Linux 'tcpdump -i any -t' form — interface + direction prefix
SAMPLE_LINUX = """\
eth0 Out IP 10.0.0.5.54321 > 1.2.3.4.443: tcp 0
wlan0 Out IP 10.0.0.5.51000 > 1.2.3.4.443: tcp 52
"""


class TestParseLine:
    def test_macos_tcp_line_no_iface(self):
        # 5-tuple now includes the payload byte count (trailing 'tcp 0' → 0)
        assert NetworkFlowsCollector._parse_line(
            "IP 10.0.0.5.54321 > 142.250.80.46.443: tcp 0"
        ) == (None, "tcp", "142.250.80.46", 443, 0)

    def test_udp_line_with_comma(self):
        # 'UDP, length 45' → 45 payload bytes
        assert NetworkFlowsCollector._parse_line(
            "IP 10.0.0.5.5353 > 224.0.0.251.5353: UDP, length 45"
        ) == (None, "udp", "224.0.0.251", 5353, 45)

    def test_linux_any_line_has_interface(self):
        # 'eth0 Out IP ...' → interface is the leading token
        assert NetworkFlowsCollector._parse_line(
            "eth0 Out IP 10.0.0.5.54321 > 1.2.3.4.443: tcp 0"
        ) == ("eth0", "tcp", "1.2.3.4", 443, 0)

    def test_arp_and_blank_skipped(self):
        assert NetworkFlowsCollector._parse_line("ARP, Request who-has x") is None
        assert NetworkFlowsCollector._parse_line("") is None

    def test_non_numeric_port_skipped(self):
        assert (
            NetworkFlowsCollector._parse_line("IP 10.0.0.5.x > host.example: tcp 0")
            is None
        )

    def test_ipv6_line_macos(self):
        # tcpdump 'IP6' lines append the port after a final '.' just like
        # IPv4, so the trailing .443 splits off the v6 destination.
        assert NetworkFlowsCollector._parse_line(
            "IP6 2600:1f18::1.50000 > 2606:4700:4700::1111.443: tcp 0"
        ) == (None, "tcp", "2606:4700:4700::1111", 443, 0)

    def test_ipv6_line_linux_any(self):
        assert NetworkFlowsCollector._parse_line(
            "eth0 Out IP6 fe80::1.5353 > 2001:4860:4860::8888.443: tcp 52"
        ) == ("eth0", "tcp", "2001:4860:4860::8888", 443, 52)

    def test_macos_k_interface_prefix(self):
        # macOS '-k I' prefixes the real interface in parentheses (verified
        # live: "(en6) IP 18.190.38.130.443 > ..."), so flows land on
        # en6/en0/… instead of the 'pktap' pseudo-device.
        assert NetworkFlowsCollector._parse_line(
            "(en6) IP 192.168.1.209.56258 > 18.190.38.130.443: tcp 0"
        ) == ("en6", "tcp", "18.190.38.130", 443, 0)

    def test_macos_k_ipv6_expanded_address(self):
        # Real macOS capture: '-k I' + IP6 + a fully-expanded v6 address
        # (no '::'); the trailing '.443' still splits off the port.
        assert NetworkFlowsCollector._parse_line(
            "(en6) IP6 2803:9810:469f:7108:f5ff:a108:be74:f78a.55987 "
            "> 2a03:2880:f205:2c6:face:b00c:0:7260.443: tcp 1380"
        ) == ("en6", "tcp", "2a03:2880:f205:2c6:face:b00c:0:7260", 443, 1380)


class TestPayloadBytes:
    def test_tcp_trailing_length(self):
        from avai.host_monitor import _payload_bytes

        assert _payload_bytes("IP a > b: tcp 1380".split()) == 1380
        assert _payload_bytes("IP a > b: tcp 0".split()) == 0

    def test_udp_length_token(self):
        from avai.host_monitor import _payload_bytes

        assert _payload_bytes("IP a > b: UDP, length 45".split()) == 45

    def test_absent_returns_zero(self):
        from avai.host_monitor import _payload_bytes

        assert _payload_bytes("IP a > b: Flags [S]".split()) == 0
        assert _payload_bytes([]) == 0


class TestIfaceFromBanner:
    def test_extracts_interface(self):
        stderr = "tcpdump: listening on en0, link-type EN10MB (Ethernet), capture..."
        assert NetworkFlowsCollector._iface_from_banner(stderr) == "en0"

    def test_none_when_absent(self):
        assert NetworkFlowsCollector._iface_from_banner("some other output") is None


class TestNormalizeDefaultIface:
    def test_pktap_pseudo_device_dropped(self):
        # 'pktap'/'pktap0' is the macOS aggregating tap, not a real iface
        assert NetworkFlowsCollector._normalize_default_iface("pktap0") is None
        assert NetworkFlowsCollector._normalize_default_iface("pktap") is None

    def test_real_interface_kept(self):
        assert NetworkFlowsCollector._normalize_default_iface("en0") == "en0"

    def test_none_passthrough(self):
        assert NetworkFlowsCollector._normalize_default_iface(None) is None


class TestAggregate:
    def test_macos_uses_default_iface_and_counts(self):
        flows = NetworkFlowsCollector()._aggregate(SAMPLE_MACOS, "en0")
        assert len(flows) == 3  # google:443 (x2), mdns, dns
        g = flows[("en0", "tcp", "142.250.80.46", 443)]
        assert g["packets"] == 2
        assert g["byte_count"] == 52  # tcp 0 + tcp 52 summed
        assert g["iface"] == "en0"

    def test_linux_per_line_interface(self):
        flows = NetworkFlowsCollector()._aggregate(SAMPLE_LINUX, None)
        # same dst:port but different interfaces → two distinct flows
        assert ("eth0", "tcp", "1.2.3.4", 443) in flows
        assert ("wlan0", "tcp", "1.2.3.4", 443) in flows

    def test_empty(self):
        assert NetworkFlowsCollector()._aggregate("", "en0") == {}


class TestFlowIndicators:
    def test_public_dst_emits_ipv4(self):
        out = extract_indicators("network_flows", {"dst_ip": "8.8.8.8", "dst_port": 53})
        assert [i.value for i in out] == ["8.8.8.8"]
        assert out[0].type is IndicatorType.IPV4

    def test_multicast_and_private_skipped(self):
        assert extract_indicators("network_flows", {"dst_ip": "224.0.0.251"}) == []
        assert extract_indicators("network_flows", {"dst_ip": "10.0.0.1"}) == []

    def test_public_ipv6_emits_ipv6(self):
        out = extract_indicators(
            "network_flows", {"dst_ip": "2606:4700:4700::1111", "dst_port": 443}
        )
        assert [(i.type, i.value) for i in out] == [
            (IndicatorType.IPV6, "2606:4700:4700::1111")
        ]

    def test_link_local_and_ula_ipv6_skipped(self):
        assert extract_indicators("network_flows", {"dst_ip": "fe80::1"}) == []
        assert extract_indicators("network_flows", {"dst_ip": "fd00::1"}) == []


@pytest.fixture
def seeded(tmp_path):
    db = tmp_path / "nf.db"
    engine = create_engine(f"sqlite:///{db}", connect_args={"check_same_thread": False})
    sink = Sink(engine)
    sink.setup()
    run_id, ts = sink.start_run("h", 5)
    from avai.host_monitor import Judgment, ThreatCategory, Verdict
    from avai.host_monitor.runtime import Digest

    fields = ("iface", "proto", "dst_ip", "dst_port")
    # two flows to the SAME bad destination on different ports + one benign
    rows = [
        {
            "iface": "en0",
            "proto": "tcp",
            "dst_ip": "203.0.113.9",
            "dst_port": 4444,
            "service": None,
            "packets": 120,
            "first_seen": ts,
            "last_seen": ts,
        },
        {
            "iface": "en0",
            "proto": "tcp",
            "dst_ip": "203.0.113.9",
            "dst_port": 8080,
            "service": "http-alt",
            "packets": 30,
            "first_seen": ts,
            "last_seen": ts,
        },
        {
            "iface": "en0",
            "proto": "tcp",
            "dst_ip": "142.250.80.46",
            "dst_port": 443,
            "service": "https",
            "packets": 500,
            "first_seen": ts,
            "last_seen": ts,
        },
    ]
    for r in rows:
        r["run_id"] = run_id
        r["collected_at"] = ts
        r["content_hash"] = Digest.of_row(r, fields)
    sink.write(NetworkFlowRow, rows)
    sink.write_judgments(
        [
            Judgment(
                content_hash=rows[0]["content_hash"],
                collector="network_flows",
                verdict=Verdict.MALICIOUS,
                category=ThreatCategory.COMMAND_AND_CONTROL,
                confidence=0.91,
                reasoning="beacon to raw IP on 4444",
                remediation="block",
                model="m",
                created_at=ts,
            )
        ]
    )
    return engine, run_id


class TestNetworkFlowsAggregation:
    def test_groups_by_destination_with_sums_and_counts(self, seeded):
        engine, run_id = seeded
        with Session(engine) as s:
            data = network_flows(s, run_id)
        rows = data["rows"]
        # 2 distinct destinations (203.0.113.9 collapses its two flows)
        assert len(rows) == 2
        bad = next(r for r in rows if r["dst_ip"] == "203.0.113.9")
        assert bad["flows"] == 2  # two ports collapsed
        assert bad["packets"] == 150  # 120 + 30 summed
        assert "4444" in bad["ports"] and "8080/http-alt" in bad["ports"]
        assert bad["iface"] == "en0"
        assert bad["verdict"] == "malicious"  # worst verdict across the group
        # malicious destination sorts first
        assert rows[0]["dst_ip"] == "203.0.113.9"

    def test_summary_totals(self, seeded):
        engine, run_id = seeded
        with Session(engine) as s:
            summary = network_flows(s, run_id)["summary"]
        assert summary["destinations"] == 2
        assert summary["flows"] == 3
        assert summary["packets"] == 650
        assert summary["malicious"] == 1

    def test_fragment_renders_interface_and_verdict(self, seeded):
        engine, run_id = seeded
        db = str(engine.url).replace("sqlite:///", "")
        app.config.update(TESTING=True, DB_PATH=db)
        with app.test_client() as c:
            html = c.get("/fragments/network-flows").data.decode()
        assert "203.0.113.9" in html
        assert "en0" in html  # interface column
        assert "malicious" in html
        assert "tcpdump aggregator" in html


class TestTrafficVolume:
    """The traffic cell leads with data volume (summed payload bytes),
    falling back to a packet count when bytes are unknown."""

    def _seed_flow(self, tmp_path, byte_count):
        from avai.host_monitor.runtime import Digest

        engine = create_engine(
            f"sqlite:///{tmp_path / 'v.db'}",
            connect_args={"check_same_thread": False},
        )
        sink = Sink(engine)
        sink.setup()
        run_id, ts = sink.start_run("h", 5)
        fields = ("iface", "proto", "dst_ip", "dst_port")
        row = {
            "iface": "en6",
            "proto": "tcp",
            "dst_ip": "203.0.113.5",
            "dst_port": 443,
            "service": "https",
            "packets": 8,
            "byte_count": byte_count,
            "process": None,
            "pid": None,
            "first_seen": ts,
            "last_seen": ts,
            "run_id": run_id,
            "collected_at": ts,
        }
        row["content_hash"] = Digest.of_row(row, fields)
        sink.write(NetworkFlowRow, [row])
        return engine, run_id

    def test_bytes_summed_and_in_summary(self, tmp_path):
        engine, run_id = self._seed_flow(tmp_path, 1_200_000)
        with Session(engine) as s:
            data = network_flows(s, run_id)
        assert data["rows"][0]["bytes"] == 1_200_000
        assert data["summary"]["bytes"] == 1_200_000

    def test_fragment_shows_human_volume(self, tmp_path):
        engine, run_id = self._seed_flow(tmp_path, 1_200_000)
        db = str(engine.url).replace("sqlite:///", "")
        app.config.update(TESTING=True, DB_PATH=db)
        with app.test_client() as c:
            html = c.get("/fragments/network-flows").data.decode()
        assert "1.1 MB" in html  # volume headline
        assert "8 pkts" in html  # packets demoted to detail line

    def test_zero_bytes_falls_back_to_packets(self, tmp_path):
        engine, run_id = self._seed_flow(tmp_path, 0)
        db = str(engine.url).replace("sqlite:///", "")
        app.config.update(TESTING=True, DB_PATH=db)
        with app.test_client() as c:
            html = c.get("/fragments/network-flows").data.decode()
        assert "8 " in html and "pkts" in html  # packet count as headline


def _seed_geo(engine, evidence: list[dict]) -> None:
    """Insert enrichment_evidence rows through the ORM model the dashboard
    queries — each entry's ``details`` dict becomes details_json, so the
    geolocation extraction runs over the same path production uses."""
    import json

    from avai.enrichers.cache import register_schema
    from avai.host_monitor import Base

    model = register_schema(Base)
    with Session(engine) as s:
        for e in evidence:
            s.add(
                model(
                    source=e.get("source", "ipwhois_geo"),
                    indicator_type=e.get("itype", "ipv4"),
                    indicator_value=e["ip"],
                    verdict_hint=e.get("hint", "unknown"),
                    confidence=e.get("confidence", 0.0),
                    summary=e.get("summary", ""),
                    details_json=json.dumps(e.get("details", {})),
                    fetched_at="2026-05-29T00:00:00",
                )
            )
        s.commit()


class TestGeolocationColumn:
    def test_geo_attached_and_richest_source_wins(self, seeded):
        engine, run_id = seeded
        # AbuseIPDB only knows country+isp; ipwho.is knows city/region/asn —
        # the richer one must win.
        _seed_geo(
            engine,
            [
                {
                    "source": "abuseipdb",
                    "ip": "203.0.113.9",
                    "hint": "malicious",
                    "details": {"countryCode": "US", "isp": "Comcast"},
                },
                {
                    "source": "ipwhois_geo",
                    "ip": "203.0.113.9",
                    "details": {
                        "country": "United States",
                        "region": "California",
                        "city": "San Jose",
                        "asn": 7922,
                        "org": "Comcast Cable",
                    },
                },
            ],
        )
        with Session(engine) as s:
            rows = network_flows(s, run_id)["rows"]
        geo = next(r for r in rows if r["dst_ip"] == "203.0.113.9")["geo"]
        assert geo is not None
        assert geo["city"] == "San Jose"
        assert geo["country"] == "United States"
        assert geo["asn"] == 7922

    def test_geo_falls_back_to_abuseipdb_fields(self, seeded):
        # No dedicated geo source — country/org still come from AbuseIPDB's
        # own details (the "use the enrich ip info" fallback).
        engine, run_id = seeded
        _seed_geo(
            engine,
            [
                {
                    "source": "abuseipdb",
                    "ip": "203.0.113.9",
                    "hint": "malicious",
                    "details": {"countryCode": "DE", "isp": "Hetzner"},
                }
            ],
        )
        with Session(engine) as s:
            rows = network_flows(s, run_id)["rows"]
        geo = next(r for r in rows if r["dst_ip"] == "203.0.113.9")["geo"]
        assert geo["country"] == "DE"
        assert geo["org"] == "Hetzner"
        assert geo["city"] is None

    def test_destination_without_evidence_has_no_geo(self, seeded):
        engine, run_id = seeded
        _seed_geo(
            engine,
            [
                {
                    "source": "ipwhois_geo",
                    "ip": "203.0.113.9",
                    "details": {"country": "US", "city": "Ashburn"},
                }
            ],
        )
        with Session(engine) as s:
            rows = network_flows(s, run_id)["rows"]
        benign = next(r for r in rows if r["dst_ip"] == "142.250.80.46")
        assert benign["geo"] is None

    def test_geo_attached_for_ipv6_destination(self, tmp_path):
        # IPv6 flows are captured + enriched too: geo evidence is keyed by
        # indicator_type='ipv6' and must still join to the flow's dst_ip.
        db = tmp_path / "v6.db"
        engine = create_engine(
            f"sqlite:///{db}", connect_args={"check_same_thread": False}
        )
        sink = Sink(engine)
        sink.setup()
        run_id, ts = sink.start_run("h", 5)
        from avai.host_monitor.runtime import Digest

        fields = ("iface", "proto", "dst_ip", "dst_port")
        row = {
            "iface": "en0",
            "proto": "tcp",
            "dst_ip": "2606:4700:4700::1111",
            "dst_port": 443,
            "service": "https",
            "packets": 7,
            "first_seen": ts,
            "last_seen": ts,
            "run_id": run_id,
            "collected_at": ts,
        }
        row["content_hash"] = Digest.of_row(row, fields)
        sink.write(NetworkFlowRow, [row])
        _seed_geo(
            engine,
            [
                {
                    "source": "ipwhois_geo",
                    "ip": "2606:4700:4700::1111",
                    "itype": "ipv6",
                    "details": {
                        "country": "United States",
                        "city": "San Francisco",
                        "asn": 13335,
                        "org": "Cloudflare, Inc.",
                    },
                }
            ],
        )
        with Session(engine) as s:
            rows = network_flows(s, run_id)["rows"]
        geo = next(r for r in rows if r["dst_ip"] == "2606:4700:4700::1111")["geo"]
        assert geo is not None
        assert geo["city"] == "San Francisco"
        assert geo["asn"] == 13335

    def test_fragment_renders_consolidated_destination(self, seeded):
        # geolocation + hostname now live inside the destination cell
        # (no separate 'location' column); the country flag is derived
        # from the 2-letter code.
        engine, run_id = seeded
        _seed_geo(
            engine,
            [
                {
                    "source": "ipwhois_geo",
                    "ip": "203.0.113.9",
                    "details": {
                        "country": "United States",
                        "country_code": "US",
                        "city": "Ashburn",
                        "asn": 14618,
                        "org": "Amazon",
                    },
                }
            ],
        )
        db = str(engine.url).replace("sqlite:///", "")
        app.config.update(TESTING=True, DB_PATH=db)
        with app.test_client() as c:
            html = c.get("/fragments/network-flows").data.decode()
        assert "203.0.113.9" in html  # the IP anchor
        assert "Ashburn" in html  # city, now in the destination cell
        assert "AS14618" in html  # ASN, now in the destination cell
        assert "\U0001F1FA\U0001F1F8" in html  # 🇺🇸 flag from country_code
        assert "threat intel" not in html  # threat-intel column removed
        # the separate location column header is gone
        assert ">location</th>" not in html

    def test_no_geo_when_evidence_table_absent(self, tmp_path):
        """Older DB lacking enrichment_evidence must not 500 — geo None."""
        from sqlalchemy import text

        db = tmp_path / "noev.db"
        engine = create_engine(
            f"sqlite:///{db}", connect_args={"check_same_thread": False}
        )
        sink = Sink(engine)
        sink.setup()
        run_id, ts = sink.start_run("h", 5)
        from avai.host_monitor.runtime import Digest

        fields = ("iface", "proto", "dst_ip", "dst_port")
        row = {
            "iface": "en0",
            "proto": "tcp",
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "service": "domain",
            "packets": 3,
            "first_seen": ts,
            "last_seen": ts,
            "run_id": run_id,
            "collected_at": ts,
        }
        row["content_hash"] = Digest.of_row(row, fields)
        sink.write(NetworkFlowRow, [row])
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE enrichment_evidence"))
        with Session(engine) as s:
            rows = network_flows(s, run_id)["rows"]
        assert rows[0]["geo"] is None


class TestFlagEmoji:
    def test_two_letter_code_to_flag(self):
        from avai.dashboard import _flag_emoji

        assert _flag_emoji("US") == "\U0001F1FA\U0001F1F8"
        assert _flag_emoji("de") == "\U0001F1E9\U0001F1EA"  # case-insensitive

    def test_non_code_returns_empty(self):
        from avai.dashboard import _flag_emoji

        assert _flag_emoji("United States") == ""
        assert _flag_emoji(None) == ""
        assert _flag_emoji("U1") == ""
        assert _flag_emoji("") == ""


class TestHumanBytes:
    def test_scales(self):
        from avai.dashboard import _human_bytes

        assert _human_bytes(927) == "927 B"
        assert _human_bytes(12345) == "12.1 KB"
        assert _human_bytes(5_000_000) == "4.8 MB"
        assert _human_bytes(3_000_000_000) == "2.8 GB"

    def test_zero_or_none_empty(self):
        from avai.dashboard import _human_bytes

        assert _human_bytes(0) == ""
        assert _human_bytes(None) == ""
        assert _human_bytes(-5) == ""


class TestDestinationHostname:
    """The destination column shows a resolved hostname/domain under the
    IP when any enrichment source named one."""

    def test_hostname_from_shodan_hostnames(self, seeded):
        engine, run_id = seeded
        _seed_geo(
            engine,
            [
                {
                    "source": "shodan_internetdb",
                    "ip": "203.0.113.9",
                    "details": {"hostnames": ["evil.example.com"], "ports": [4444]},
                }
            ],
        )
        with Session(engine) as s:
            rows = network_flows(s, run_id)["rows"]
        bad = next(r for r in rows if r["dst_ip"] == "203.0.113.9")
        assert bad["hostname"] == "evil.example.com"

    def test_hostname_falls_back_to_abuseipdb_domain(self, seeded):
        engine, run_id = seeded
        _seed_geo(
            engine,
            [
                {
                    "source": "abuseipdb",
                    "ip": "203.0.113.9",
                    "hint": "malicious",
                    "details": {"domain": "bad-host.net", "countryCode": "US"},
                }
            ],
        )
        with Session(engine) as s:
            rows = network_flows(s, run_id)["rows"]
        bad = next(r for r in rows if r["dst_ip"] == "203.0.113.9")
        assert bad["hostname"] == "bad-host.net"

    def test_destination_without_hostname_is_none(self, seeded):
        engine, run_id = seeded
        _seed_geo(
            engine,
            [
                {
                    "source": "ipwhois_geo",
                    "ip": "203.0.113.9",
                    "details": {"country": "US", "city": "Ashburn"},
                }
            ],
        )
        with Session(engine) as s:
            rows = network_flows(s, run_id)["rows"]
        bad = next(r for r in rows if r["dst_ip"] == "203.0.113.9")
        assert bad["hostname"] is None

    def test_fragment_renders_hostname_in_destination(self, seeded):
        engine, run_id = seeded
        _seed_geo(
            engine,
            [
                {
                    "source": "shodan_internetdb",
                    "ip": "203.0.113.9",
                    "details": {"hostnames": ["host.evil.example"]},
                }
            ],
        )
        db = str(engine.url).replace("sqlite:///", "")
        app.config.update(TESTING=True, DB_PATH=db)
        with app.test_client() as c:
            html = c.get("/fragments/network-flows").data.decode()
        assert "host.evil.example" in html


class TestMissingTableGraceful:
    """Simulate a DB written by an older monitor that predates this
    collector: full schema, then drop network_flows. The dashboard must
    degrade to empty, not 500."""

    def _db_without_flows(self, tmp_path):
        from sqlalchemy import text

        db = tmp_path / "old.db"
        engine = create_engine(
            f"sqlite:///{db}", connect_args={"check_same_thread": False}
        )
        sink = Sink(engine)
        sink.setup()
        sink.start_run("h", 5)
        sink.end_run(ok=1, failed=0)
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE network_flows"))
        return engine, db

    def test_returns_empty_when_table_absent(self, tmp_path):
        engine, _ = self._db_without_flows(tmp_path)
        with Session(engine) as s:
            data = network_flows(s, "x")
        assert data["rows"] == []
        assert data["summary"]["destinations"] == 0

    def test_fragment_200_on_db_without_table(self, tmp_path):
        engine, db = self._db_without_flows(tmp_path)
        engine.dispose()
        app.config.update(TESTING=True, DB_PATH=str(db))
        with app.test_client() as c:
            r = c.get("/fragments/network-flows")
        assert r.status_code == 200
        assert "no network flows match the current filters" in r.data.decode()

    def test_row_counts_skips_missing_table(self, tmp_path):
        from avai.dashboard import row_counts

        engine, _ = self._db_without_flows(tmp_path)
        with Session(engine) as s:
            counts = row_counts(s, "some-run", "2000-01-01")
        names = {c["name"] for c in counts}
        assert "network_flows" not in names
        assert "processes" in names


class TestMissingColumnGraceful:
    """network_flows table written by an OLDER monitor lacks the iface
    column; the read-only dashboard can't migrate it, so the query must
    tolerate the missing column instead of 500-ing."""

    def test_handles_table_without_iface_column(self, tmp_path):
        from sqlalchemy import text

        db = tmp_path / "noiface.db"
        engine = create_engine(
            f"sqlite:///{db}", connect_args={"check_same_thread": False}
        )
        sink = Sink(engine)
        sink.setup()
        run_id, ts = sink.start_run("h", 5)
        # simulate the pre-iface schema: drop the column
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE network_flows DROP COLUMN iface"))
            conn.execute(
                text(
                    "INSERT INTO network_flows "
                    "(run_id, collected_at, content_hash, proto, dst_ip, dst_port, "
                    " service, packets) "
                    "VALUES (:r, :t, 'h1', 'tcp', '8.8.8.8', 443, 'https', 5)"
                ),
                {"r": run_id, "t": ts},
            )
        with Session(engine) as s:
            data = network_flows(s, run_id)
        assert data["summary"]["destinations"] == 1
        assert data["rows"][0]["dst_ip"] == "8.8.8.8"
        assert data["rows"][0]["iface"] == "—"  # NULL → rendered placeholder
