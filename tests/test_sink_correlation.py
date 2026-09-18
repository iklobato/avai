"""Sink.correlation_context: the runtime behaviour attached to a process
finding. Each signal is keyed by PID, except DNS, which is keyed by process
name because that is all DNS capture records."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine

from avai.host_monitor import Sink
from avai.host_monitor.models import (
    DnsQueryRow,
    ListeningPortRow,
    NetworkConnectionRow,
    NetworkFlowRow,
    ProcessExecRow,
)

_OLD = "2026-01-01T00:00:00+00:00"
_NEW = "2026-01-02T00:00:00+00:00"


@pytest.fixture
def sink():
    s = Sink(create_engine("sqlite:///:memory:"))
    s.setup()
    return s


def _write(sink, model, rows, collected_at=_NEW):
    sink.write(
        model,
        [
            {
                "run_id": "r",
                "collected_at": collected_at,
                "content_hash": f"h{i}",
                **row,
            }
            for i, row in enumerate(rows)
        ],
    )


def _port(pid, port):
    return {"pid": pid, "laddr_ip": "0.0.0.0", "laddr_port": port}


class TestSignals:
    def test_each_signal_is_keyed_by_pid_and_dns_by_name(self, sink):
        _write(sink, ListeningPortRow, [_port(7, 22)])
        _write(
            sink,
            NetworkFlowRow,
            [
                {
                    "pid": 7,
                    "dst_ip": "1.2.3.4",
                    "dst_port": 443,
                    "service": "https",
                    "packets": 9,
                }
            ],
        )
        _write(
            sink,
            NetworkConnectionRow,
            [
                {
                    "pid": 7,
                    "raddr_ip": "5.6.7.8",
                    "raddr_port": 80,
                    "status": "ESTABLISHED",
                }
            ],
        )
        _write(
            sink,
            ProcessExecRow,
            [
                {
                    "pid": 7,
                    "parent_path": "/bin/sh",
                    "signing_id": "x.y",
                    "exe_path": "/usr/bin/z",
                }
            ],
        )
        _write(
            sink, DnsQueryRow, [{"process": "sshd", "qname": "a.example", "qtype": "A"}]
        )

        ctx = sink.correlation_context([7], ["sshd"], None)

        assert ctx == {
            "ports": {7: ["0.0.0.0:22"]},
            "flows": {7: [{"dst": "1.2.3.4:443", "service": "https", "packets": 9}]},
            "conns": {7: ["5.6.7.8:80 ESTABLISHED"]},
            "dns": {"sshd": ["a.example (A)"]},
            "exec": {7: {"parent": "/bin/sh", "signed": "x.y", "exe": "/usr/bin/z"}},
        }

    def test_other_pids_and_names_are_left_out(self, sink):
        _write(sink, ListeningPortRow, [_port(8, 22)])
        _write(
            sink, DnsQueryRow, [{"process": "curl", "qname": "a.example", "qtype": "A"}]
        )

        ctx = sink.correlation_context([7], ["sshd"], None)

        assert ctx["ports"] == {} and ctx["dns"] == {}

    def test_connections_without_a_remote_address_are_skipped(self, sink):
        _write(
            sink,
            NetworkConnectionRow,
            [{"pid": 7, "raddr_ip": None, "raddr_port": None, "status": "LISTEN"}],
        )

        assert sink.correlation_context([7], [], None)["conns"] == {}

    def test_flows_are_ordered_busiest_first(self, sink):
        _write(
            sink,
            NetworkFlowRow,
            [
                {
                    "pid": 7,
                    "dst_ip": "1.1.1.1",
                    "dst_port": 53,
                    "service": None,
                    "packets": 1,
                },
                {
                    "pid": 7,
                    "dst_ip": "2.2.2.2",
                    "dst_port": 53,
                    "service": None,
                    "packets": 50,
                },
            ],
        )

        flows = sink.correlation_context([7], [], None)["flows"][7]

        assert [f["packets"] for f in flows] == [50, 1]

    def test_exec_keeps_the_most_recent_event_per_pid(self, sink):
        _write(
            sink,
            ProcessExecRow,
            [
                {
                    "pid": 7,
                    "exe_path": "/old",
                    "event_timestamp": "2026-01-01T00:00:00",
                },
                {
                    "pid": 7,
                    "exe_path": "/new",
                    "event_timestamp": "2026-01-01T00:00:09",
                },
            ],
        )

        assert sink.correlation_context([7], [], None)["exec"][7]["exe"] == "/new"


class TestBounds:
    def test_since_drops_rows_collected_before_it(self, sink):
        _write(sink, ListeningPortRow, [_port(7, 22)], collected_at=_OLD)
        _write(sink, ListeningPortRow, [_port(7, 80)], collected_at=_NEW)
        _write(
            sink, DnsQueryRow, [{"process": "p", "qname": "old", "qtype": "A"}], _OLD
        )

        ctx = sink.correlation_context([7], ["p"], _NEW)

        assert ctx["ports"] == {7: ["0.0.0.0:80"]}
        assert ctx["dns"] == {}

    def test_since_none_reads_the_full_history(self, sink):
        _write(sink, ListeningPortRow, [_port(7, 22)], collected_at=_OLD)

        assert sink.correlation_context([7], [], None)["ports"] == {7: ["0.0.0.0:22"]}

    def test_per_pid_lists_are_capped(self, sink):
        _write(sink, ListeningPortRow, [_port(7, p) for p in range(1, 6)])

        ports = sink.correlation_context([7], [], None, per_pid_cap=3)["ports"][7]

        assert len(ports) == 3

    def test_dns_gets_five_more_than_the_per_pid_cap(self, sink):
        _write(
            sink,
            DnsQueryRow,
            [{"process": "p", "qname": f"q{i}", "qtype": "A"} for i in range(20)],
        )

        dns = sink.correlation_context([], ["p"], None, per_pid_cap=3)["dns"]["p"]

        assert len(dns) == 8


class TestEmptyInput:
    @pytest.mark.parametrize("pids,names", [([], []), ([None], [""]), ([None], [])])
    def test_no_usable_pid_or_name_returns_empty_signals(self, sink, pids, names):
        _write(sink, ListeningPortRow, [_port(None, 22)])

        ctx = sink.correlation_context(pids, names, None)

        assert ctx == {"ports": {}, "flows": {}, "conns": {}, "dns": {}, "exec": {}}

    def test_names_alone_still_read_dns(self, sink):
        _write(sink, ListeningPortRow, [_port(7, 22)])
        _write(sink, DnsQueryRow, [{"process": "p", "qname": "q", "qtype": "A"}])

        ctx = sink.correlation_context([None], ["p"], None)

        assert ctx["dns"] == {"p": ["q (A)"]} and ctx["ports"] == {}
