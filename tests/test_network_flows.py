"""Tests for the tcpdump flow aggregator collector + its dashboard table.

The live capture needs root, so these don't run tcpdump — they feed
canned ``tcpdump -q`` output through the parser/aggregator (the part
that has the bugs), test the indicator extraction, and render the
dashboard table from seeded rows.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from avai.dashboard import _ensure_db_exists, app, network_flows
from avai.enrichers import IndicatorType, extract_indicators
from avai.host_monitor import NetworkFlowRow, NetworkFlowsCollector, Sink

SAMPLE = """\
13:00:00.1 IP 10.0.0.5.54321 > 142.250.80.46.443: tcp 0
13:00:00.2 IP 10.0.0.5.54322 > 142.250.80.46.443: tcp 52
13:00:00.3 IP 10.0.0.5.5353 > 224.0.0.251.5353: UDP, length 45
ARP, Request who-has 10.0.0.1 tell 10.0.0.5, length 28
13:00:00.4 IP 10.0.0.5.51000 > 8.8.8.8.53: UDP, length 30

"""


# ---------------------------------------------------------------------------
# _parse_line — split-based extraction (no regex)
# ---------------------------------------------------------------------------


class TestParseLine:
    def test_tcp_line(self):
        assert NetworkFlowsCollector._parse_line(
            "13:00 IP 10.0.0.5.54321 > 142.250.80.46.443: tcp 0"
        ) == ("tcp", "142.250.80.46", 443)

    def test_udp_line_with_comma(self):
        assert NetworkFlowsCollector._parse_line(
            "13:00 IP 10.0.0.5.5353 > 224.0.0.251.5353: UDP, length 45"
        ) == ("udp", "224.0.0.251", 5353)

    def test_arp_line_is_skipped(self):
        assert (
            NetworkFlowsCollector._parse_line(
                "ARP, Request who-has 10.0.0.1 tell 10.0.0.5, length 28"
            )
            is None
        )

    def test_blank_line_is_skipped(self):
        assert NetworkFlowsCollector._parse_line("") is None
        assert NetworkFlowsCollector._parse_line("   ") is None

    def test_no_direction_arrow_is_skipped(self):
        assert NetworkFlowsCollector._parse_line("garbage without arrow") is None

    def test_non_numeric_port_is_skipped(self):
        # malformed dst with a non-numeric "port"
        assert (
            NetworkFlowsCollector._parse_line(
                "13:00 IP 10.0.0.5.x > host.example: tcp 0"
            )
            is None
        )


# ---------------------------------------------------------------------------
# _aggregate — flows deduped + packet counts
# ---------------------------------------------------------------------------


class TestAggregate:
    def test_aggregates_and_counts(self):
        flows = NetworkFlowsCollector()._aggregate(SAMPLE)
        # 3 distinct flows: 142.250.80.46:443 (x2), 224.0.0.251:5353, 8.8.8.8:53
        assert len(flows) == 3
        google = flows[("tcp", "142.250.80.46", 443)]
        assert google["packets"] == 2  # two packets collapsed into one flow
        assert flows[("udp", "8.8.8.8", 53)]["packets"] == 1
        # service name resolution is best-effort; key fields are exact
        assert google["dst_ip"] == "142.250.80.46"
        assert google["dst_port"] == 443

    def test_empty_capture_yields_no_flows(self):
        assert NetworkFlowsCollector()._aggregate("") == {}


# ---------------------------------------------------------------------------
# Indicator extraction — public dst enriched, private/multicast skipped
# ---------------------------------------------------------------------------


class TestFlowIndicators:
    def test_public_dst_emits_ipv4(self):
        out = extract_indicators("network_flows", {"dst_ip": "8.8.8.8", "dst_port": 53})
        assert len(out) == 1
        assert out[0].type is IndicatorType.IPV4
        assert out[0].value == "8.8.8.8"

    def test_multicast_dst_skipped(self):
        # 224.0.0.251 (mDNS) is multicast → not enriched
        assert (
            extract_indicators(
                "network_flows", {"dst_ip": "224.0.0.251", "dst_port": 5353}
            )
            == []
        )

    def test_private_dst_skipped(self):
        assert (
            extract_indicators("network_flows", {"dst_ip": "10.0.0.1", "dst_port": 443})
            == []
        )


# ---------------------------------------------------------------------------
# Dashboard table — service query + rendering
# ---------------------------------------------------------------------------


@pytest.fixture
def seeded(tmp_path):
    db = tmp_path / "nf.db"
    engine = create_engine(f"sqlite:///{db}", connect_args={"check_same_thread": False})
    sink = Sink(engine)
    sink.setup()
    run_id, ts = sink.start_run("h", 5)
    from avai.host_monitor import Judgment, ThreatCategory, Verdict, content_hash

    fields = ("proto", "dst_ip", "dst_port")
    rows = [
        {
            "proto": "tcp",
            "dst_ip": "203.0.113.9",
            "dst_port": 4444,
            "service": None,
            "packets": 120,
            "first_seen": ts,
            "last_seen": ts,
        },
        {
            "proto": "tcp",
            "dst_ip": "142.250.80.46",
            "dst_port": 443,
            "service": "https",
            "packets": 30,
            "first_seen": ts,
            "last_seen": ts,
        },
    ]
    for r in rows:
        r["run_id"] = run_id
        r["collected_at"] = ts
        r["content_hash"] = content_hash(r, fields)
    sink.write(NetworkFlowRow, rows)
    # judge the first flow malicious, leave the second unjudged
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


class TestNetworkFlowsTable:
    def test_service_query_joins_verdict_and_orders_worst_first(self, seeded):
        engine, run_id = seeded
        with Session(engine) as s:
            flows = network_flows(s, run_id)
        assert len(flows) == 2
        # malicious flow sorts first despite fewer... (it has MORE packets too)
        assert flows[0]["verdict"] == "malicious"
        assert flows[0]["dst_port"] == 4444
        assert flows[0]["reasoning"] == "beacon to raw IP on 4444"
        # the unjudged flow has verdict None
        assert flows[1]["verdict"] is None
        assert flows[1]["service"] == "https"

    def test_fragment_renders_with_flows(self, seeded, tmp_path):
        engine, run_id = seeded
        # point the dashboard at this DB and render the fragment
        db = str(engine.url).replace("sqlite:///", "")
        app.config.update(TESTING=True, DB_PATH=db)
        with app.test_client() as c:
            r = c.get("/fragments/network-flows")
        assert r.status_code == 200
        html = r.data.decode()
        assert "203.0.113.9" in html
        assert "malicious" in html
        assert "tcpdump aggregator" in html

    def test_fragment_empty_db_renders_hint(self, tmp_path):
        db = tmp_path / "empty.db"
        _ensure_db_exists(str(db))
        app.config.update(TESTING=True, DB_PATH=str(db))
        with app.test_client() as c:
            r = c.get("/fragments/network-flows")
        assert r.status_code == 200
        assert "no network flows yet" in r.data.decode()
