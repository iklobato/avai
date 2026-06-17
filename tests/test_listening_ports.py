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

from avai.dashboard import _addr_scope, app, listening_ports
from avai.host_monitor.runtime import Digest
from avai.host_monitor import (
    Judgment,
    ListeningPortRow,
    NetworkConnectionRow,
    ProcessRow,
    Sink,
    ThreatCategory,
    Verdict,
)

LP_FIELDS = ("process_name", "family", "type", "laddr_ip", "laddr_port")


class TestAddrScope:
    def test_wildcard_is_all_interfaces(self):
        assert _addr_scope("0.0.0.0") == "all"
        assert _addr_scope("::") == "all"

    def test_loopback_local_only(self):
        assert _addr_scope("127.0.0.1") == "loopback"
        assert _addr_scope("::1") == "loopback"

    def test_routable_is_specific(self):
        assert _addr_scope("192.168.1.10") == "specific"

    def test_blank_or_garbage_unknown(self):
        assert _addr_scope("") == "unknown"
        assert _addr_scope(None) == "unknown"
        assert _addr_scope("not-an-ip") == "unknown"


@pytest.fixture
def seeded(tmp_path):
    """A run with three listeners: an SSH daemon exposed on all interfaces
    (judged malicious), the same daemon's IPv6 wildcard socket on the same
    port (must collapse into the one row), and a loopback-only Postgres.
    Plus a processes snapshot and one established connection on :22."""
    db = tmp_path / "lp.db"
    engine = create_engine(f"sqlite:///{db}", connect_args={"check_same_thread": False})
    sink = Sink(engine)
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
        p["content_hash"] = Digest.of_row(p, LP_FIELDS)
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
    def test_wildcard_v4_v6_collapse_to_one_row(self, seeded):
        engine, run_id = seeded
        with Session(engine) as s:
            rows = listening_ports(s, run_id)["rows"]
        # two distinct listeners: sshd:22 (v4+v6 merged) and postgres:5432
        assert len(rows) == 2
        ssh = next(r for r in rows if r["port"] == 22)
        assert ssh["pid"] == 501
        assert set(ssh["family"]) == {"IPv4", "IPv6"}
        assert ssh["proto"] == ["TCP"]
        assert set(ssh["addrs"]) == {"0.0.0.0", "::"}

    def test_worst_verdict_and_sort_order(self, seeded):
        engine, run_id = seeded
        with Session(engine) as s:
            rows = listening_ports(s, run_id)["rows"]
        # malicious sorts first
        assert rows[0]["port"] == 22
        assert rows[0]["verdict"] == "malicious"
        assert rows[0]["confidence"] == pytest.approx(0.88)

    def test_bind_scope_signals_exposure(self, seeded):
        engine, run_id = seeded
        with Session(engine) as s:
            rows = listening_ports(s, run_id)["rows"]
        ssh = next(r for r in rows if r["port"] == 22)
        pg = next(r for r in rows if r["port"] == 5432)
        assert ssh["scope"] == "all" and ssh["exposed"] is True
        assert pg["scope"] == "loopback" and pg["exposed"] is False

    def test_process_enrichment_attached(self, seeded):
        engine, run_id = seeded
        with Session(engine) as s:
            rows = listening_ports(s, run_id)["rows"]
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

    def test_established_connection_count(self, seeded):
        engine, run_id = seeded
        with Session(engine) as s:
            rows = listening_ports(s, run_id)["rows"]
        ssh = next(r for r in rows if r["port"] == 22)
        pg = next(r for r in rows if r["port"] == 5432)
        assert ssh["conns"] == 1  # only the ESTABLISHED row counts
        assert pg["conns"] == 0

    def test_summary_totals(self, seeded):
        engine, run_id = seeded
        with Session(engine) as s:
            summary = listening_ports(s, run_id)["summary"]
        assert summary["ports"] == 2
        assert summary["exposed"] == 1  # only sshd:22 is non-loopback
        assert summary["malicious"] == 1
        assert summary["suspicious"] == 0


class TestFragmentRender:
    def test_renders_port_process_and_verdict(self, seeded):
        engine, run_id = seeded
        db = str(engine.url).replace("sqlite:///", "")
        app.config.update(TESTING=True, DB_PATH=db)
        with app.test_client() as c:
            html = c.get("/fragments/listening-ports").data.decode()
        assert ":22" in html
        assert "sshd" in html
        assert "root" in html
        assert "/usr/sbin/sshd" in html
        assert "malicious" in html
        assert "all interfaces" in html  # bind-scope badge
        assert "listening ports" in html


class TestMissingTableGraceful:
    def _db_without_ports(self, tmp_path):
        db = tmp_path / "old.db"
        engine = create_engine(
            f"sqlite:///{db}", connect_args={"check_same_thread": False}
        )
        sink = Sink(engine)
        sink.setup()
        sink.start_run("h", 5)
        sink.end_run(ok=1, failed=0)
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE listening_ports"))
        return engine, db

    def test_returns_empty_when_table_absent(self, tmp_path):
        engine, _ = self._db_without_ports(tmp_path)
        with Session(engine) as s:
            data = listening_ports(s, "x")
        assert data["rows"] == []
        assert data["summary"]["ports"] == 0

    def test_fragment_200_on_db_without_table(self, tmp_path):
        engine, db = self._db_without_ports(tmp_path)
        engine.dispose()
        app.config.update(TESTING=True, DB_PATH=str(db))
        with app.test_client() as c:
            r = c.get("/fragments/listening-ports")
        # missing table degrades to the empty-state card, not a 500
        assert r.status_code == 200
        assert "no listening sockets match the current filters" in r.data.decode()
