"""Tests for the listening-ports dashboard table.

The collector itself just maps psutil's CONN_LISTEN sockets to rows (and
needs root for full pid visibility), so these focus on the dashboard
query/render: per-(port, pid) rollup, the LLM-verdict join, the bind-scope
threat signal, enrichment from the ``processes`` snapshot + established
connection counts, and graceful behaviour when the table is absent.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from avai.dashboard.app import DashboardApp
from avai.dashboard.config import DashboardConfig
from avai.dashboard.queries import PortQuery, PortsPanel, RowFilter
from avai.dashboard.queries import BindScope
from avai.host_monitor.enums import ThreatCategory, Verdict
from avai.host_monitor.judge import Judgment
from avai.host_monitor.models import ListeningPortRow, NetworkConnectionRow, ProcessRow
from avai.host_monitor.runtime import Digest
from avai.host_monitor.sink import Sink
from pathlib import Path

LP_FIELDS = ("process_name", "family", "type", "laddr_ip", "laddr_port")


class TestAddrScope:
    def test_wildcard_is_all_interfaces(self) -> None:
        assert BindScope().of("0.0.0.0") == "all"
        assert BindScope().of("::") == "all"

    def test_loopback_local_only(self) -> None:
        assert BindScope().of("127.0.0.1") == "loopback"
        assert BindScope().of("::1") == "loopback"

    def test_routable_is_specific(self) -> None:
        assert BindScope().of("192.168.1.10") == "specific"

    def test_blank_or_garbage_unknown(self) -> None:
        assert BindScope().of("") == "unknown"
        assert BindScope().of(None) == "unknown"
        assert BindScope().of("not-an-ip") == "unknown"


@pytest.fixture
def seeded(tmp_path: Path):
    """A run with three listeners: an SSH daemon exposed on all interfaces
    (judged malicious), the same daemon's IPv6 wildcard socket on the same
    port (must collapse into the one row), and a loopback-only Postgres.
    Plus a processes snapshot and one established connection on :22."""
    db = tmp_path / "lp.db"
    engine = create_engine(f"sqlite:///{db}", connect_args={"check_same_thread": False})
    sink = Sink.create(engine)
    sink.setup()
    run_id, ts = sink.start_run("h", 5)

    ports = [
        {
            "pid": 501,
            "process_name": "sshd",
            "family": "AF_INET",
            "type": "SOCK_STREAM",
            "laddr_ip": "0.0.0.0",
            "laddr_port": 22,
        },
        {
            "pid": 501,
            "process_name": "sshd",
            "family": "AF_INET6",
            "type": "SOCK_STREAM",
            "laddr_ip": "::",
            "laddr_port": 22,
        },
        {
            "pid": 777,
            "process_name": "postgres",
            "family": "AF_INET",
            "type": "SOCK_STREAM",
            "laddr_ip": "127.0.0.1",
            "laddr_port": 5432,
        },
    ]
    for p in ports:
        p["run_id"] = run_id
        p["collected_at"] = ts
        p["content_hash"] = Digest().of_row(p, LP_FIELDS)
    sink.write(ListeningPortRow, ports)

    sink.write(
        ProcessRow,
        [
            {
                "run_id": run_id,
                "collected_at": ts,
                "pid": 501,
                "ppid": 1,
                "name": "sshd",
                "exe": "/usr/sbin/sshd",
                "cmdline_json": json.dumps(["/usr/sbin/sshd", "-D"]),
                "username": "root",
                "uid": 0,
                "status": "running",
                "cpu_percent": 0.3,
                "memory_rss": 5_242_880,
                "num_fds": 12,
                "num_threads": 1,
            }
        ],
    )

    # one live client talking to :22 → conns == 1; benign LISTEN ignored
    sink.write(
        NetworkConnectionRow,
        [
            {
                "run_id": run_id,
                "collected_at": ts,
                "pid": 501,
                "family": "AF_INET",
                "type": "SOCK_STREAM",
                "laddr_ip": "10.0.0.5",
                "laddr_port": 22,
                "raddr_ip": "203.0.113.20",
                "raddr_port": 51000,
                "status": "ESTABLISHED",
            },
            {
                "run_id": run_id,
                "collected_at": ts,
                "pid": 501,
                "family": "AF_INET",
                "type": "SOCK_STREAM",
                "laddr_ip": "0.0.0.0",
                "laddr_port": 22,
                "raddr_ip": None,
                "raddr_port": None,
                "status": "LISTEN",
            },
        ],
    )

    sink.write_judgments(
        [
            Judgment(
                content_hash=ports[0]["content_hash"],
                collector="listening_ports",
                verdict=Verdict.MALICIOUS,
                category=ThreatCategory.INITIAL_ACCESS,
                confidence=0.88,
                reasoning="sshd exposed to the internet on 0.0.0.0",
                remediation="bind to a VPN interface",
                model="m",
                created_at=ts,
            )
        ]
    )
    return engine, run_id


class TestListeningPortsRollup:
    def test_verdict_filter_uses_the_picked_verdict(self, seeded) -> None:
        # Regression: the row loop reused the name ``verdict``, so the filter
        # and its echo took the last socket's verdict instead of the user's.
        engine, run_id = seeded
        with Session(engine) as session:
            data = PortsPanel(session, run_id).ports(PortQuery(filters=RowFilter(verdict="malicious")))
        assert [r["port"] for r in data["rows"]] == [22]
        assert data["verdict"] == "malicious"

    def test_wildcard_v4_v6_collapse_to_one_row(self, seeded) -> None:
        engine, run_id = seeded
        with Session(engine) as session:
            rows = PortsPanel(session, run_id).ports(PortQuery())["rows"]
        # two distinct listeners: sshd:22 (v4+v6 merged) and postgres:5432
        assert len(rows) == 2
        ssh = next(r for r in rows if r["port"] == 22)
        assert ssh["pid"] == 501
        assert set(ssh["family"]) == {"IPv4", "IPv6"}
        assert ssh["proto"] == ["TCP"]
        assert set(ssh["addrs"]) == {"0.0.0.0", "::"}

    def test_worst_verdict_and_sort_order(self, seeded) -> None:
        engine, run_id = seeded
        with Session(engine) as session:
            rows = PortsPanel(session, run_id).ports(PortQuery())["rows"]
        # malicious sorts first
        assert rows[0]["port"] == 22
        assert rows[0]["verdict"] == "malicious"
        assert rows[0]["confidence"] == pytest.approx(0.88)

    def test_bind_scope_signals_exposure(self, seeded) -> None:
        engine, run_id = seeded
        with Session(engine) as session:
            rows = PortsPanel(session, run_id).ports(PortQuery())["rows"]
        ssh = next(r for r in rows if r["port"] == 22)
        pg = next(r for r in rows if r["port"] == 5432)
        assert ssh["scope"] == "all" and ssh["exposed"] is True
        assert pg["scope"] == "loopback" and pg["exposed"] is False

    def test_process_enrichment_attached(self, seeded) -> None:
        engine, run_id = seeded
        with Session(engine) as session:
            rows = PortsPanel(session, run_id).ports(PortQuery())["rows"]
        ssh = next(r for r in rows if r["port"] == 22)
        proc = ssh["proc"]
        assert proc["username"] == "root"
        assert proc["uid"] == 0
        assert proc["exe"] == "/usr/sbin/sshd"
        assert proc["cmdline"] == "/usr/sbin/sshd -D"
        assert proc["memory_rss"] == 5_242_880
        # postgres has no process row → proc is None, not a crash
        pg = next(r for r in rows if r["port"] == 5432)
        assert pg["proc"] is None

    def test_established_connection_count(self, seeded) -> None:
        engine, run_id = seeded
        with Session(engine) as session:
            rows = PortsPanel(session, run_id).ports(PortQuery())["rows"]
        ssh = next(r for r in rows if r["port"] == 22)
        pg = next(r for r in rows if r["port"] == 5432)
        assert ssh["conns"] == 1  # only the ESTABLISHED row counts
        assert pg["conns"] == 0

    def test_summary_totals(self, seeded) -> None:
        engine, run_id = seeded
        with Session(engine) as session:
            summary = PortsPanel(session, run_id).ports(PortQuery())["summary"]
        assert summary["ports"] == 2
        assert summary["exposed"] == 1  # only sshd:22 is non-loopback
        assert summary["malicious"] == 1
        assert summary["suspicious"] == 0


class TestFragmentRender:
    def test_renders_port_process_and_verdict(self, seeded) -> None:
        engine, run_id = seeded
        db = str(engine.url).replace("sqlite:///", "")
        with DashboardApp(DashboardConfig(db_path=db)).build().test_client() as c:
            html = c.get("/fragments/listening-ports").data.decode()
        assert ":22" in html
        assert "sshd" in html
        assert "root" in html
        assert "/usr/sbin/sshd" in html
        assert "malicious" in html
        assert "all interfaces" in html  # bind-scope badge
        assert "listening ports" in html


class TestMissingTableGraceful:
    def _db_without_ports(self, tmp_path: Path):
        db = tmp_path / "old.db"
        engine = create_engine(
            f"sqlite:///{db}", connect_args={"check_same_thread": False}
        )
        sink = Sink.create(engine)
        sink.setup()
        run_id, _ = sink.start_run("h", 5)
        sink.end_run(run_id, ok=1, failed=0)
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE listening_ports"))
        return engine, db

    def test_returns_empty_when_table_absent(self, tmp_path: Path) -> None:
        engine, _ = self._db_without_ports(tmp_path)
        with Session(engine) as session:
            data = PortsPanel(session, "x").ports(PortQuery())
        assert data["rows"] == []
        assert data["summary"]["ports"] == 0

    def test_fragment_200_on_db_without_table(self, tmp_path: Path) -> None:
        engine, db = self._db_without_ports(tmp_path)
        engine.dispose()
        with DashboardApp(DashboardConfig(db_path=str(db))).build().test_client() as c:
            response = c.get("/fragments/listening-ports")
        # missing table degrades to the empty-state card, not a 500
        assert response.status_code == 200
        assert "no listening sockets match the current filters" in response.data.decode()
