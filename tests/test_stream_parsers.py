"""Unit tests for the streaming LineParser strategies and the shared
JsonLineStreamSource. These were untested while the logic lived inline in
each collector's stream() method."""

from __future__ import annotations

import sys
import threading

from avai.host_monitor.collectors import (
    AuditExecParser,
    EsloggerExecParser,
    JournalAuthParser,
    UnifiedLogAuthParser,
)
from avai.host_monitor.runtime import JsonLineStreamSource


class TestUnifiedLogAuthParser:
    def test_maps_fields(self):
        row = UnifiedLogAuthParser().parse(
            {
                "timestamp": "2026-06-03 00:00:00",
                "processImagePath": "/usr/sbin/sshd",
                "subsystem": "com.apple.sshd",
                "category": "auth",
                "eventType": "logEvent",
                "eventMessage": "Accepted publickey",
                "processID": 42,
            }
        )
        assert row["process"] == "/usr/sbin/sshd"
        assert row["subsystem"] == "com.apple.sshd"
        assert row["pid"] == 42
        assert row["event_message"] == "Accepted publickey"
        assert "raw_json" in row


class TestJournalAuthParser:
    def test_converts_microsecond_timestamp_and_pid(self):
        row = JournalAuthParser().parse(
            {
                "__REALTIME_TIMESTAMP": "1700000000000000",
                "_PID": "1234",
                "_EXE": "/usr/sbin/sshd",
                "_SYSTEMD_UNIT": "sshd.service",
                "SYSLOG_FACILITY": "10",
                "PRIORITY": "6",
                "MESSAGE": "Accepted password",
            }
        )
        assert row["event_timestamp"] == "2023-11-14T22:13:20+00:00"
        assert row["pid"] == 1234
        assert row["process"] == "/usr/sbin/sshd"
        assert row["subsystem"] == "sshd.service"
        assert row["event_type"] == "priority=6"

    def test_missing_pid_and_timestamp_are_none(self):
        row = JournalAuthParser().parse({"MESSAGE": "x"})
        assert row["pid"] is None
        assert row["event_timestamp"] is None
        assert row["subsystem"] == "syslog"  # fallback

    def test_bad_pid_does_not_raise(self):
        row = JournalAuthParser().parse({"_PID": "notanint"})
        assert row["pid"] is None


class TestEsloggerExecParser:
    def test_extracts_nested_es_event(self):
        row = EsloggerExecParser().parse(
            {
                "time": "2026-06-03T00:00:00Z",
                "event": {
                    "exec": {
                        "target": {
                            "executable": {"path": "/bin/ls"},
                            "audit_token": {"pid": 10, "ruid": 501},
                            "signing_id": "com.apple.ls",
                        },
                        "args": ["ls", "-la"],
                    }
                },
                "process": {
                    "executable": {"path": "/bin/zsh"},
                    "audit_token": {"pid": 9},
                },
            }
        )
        assert row["exe_path"] == "/bin/ls"
        assert row["pid"] == 10
        assert row["ppid"] == 9
        assert row["uid"] == 501
        assert row["parent_path"] == "/bin/zsh"
        assert row["signing_id"] == "com.apple.ls"
        assert row["exe_args_json"] == '["ls", "-la"]'

    def test_empty_event_is_safe(self):
        row = EsloggerExecParser().parse({})
        assert row["exe_path"] is None
        assert row["event_type"] == "exec"


class TestAuditExecParser:
    def test_maps_audit_fields(self):
        row = AuditExecParser().parse(
            {
                "__REALTIME_TIMESTAMP": "1700000000000000",
                "_PID": "55",
                "_UID": "0",
                "_AUDIT_TYPE_NAME": "EXECVE",
                "EXE": "/usr/bin/curl",
            }
        )
        assert row["exe_path"] == "/usr/bin/curl"
        assert row["pid"] == 55
        assert row["uid"] == 0
        assert row["event_type"] == "EXECVE"

    def test_bad_uid_is_none(self):
        row = AuditExecParser().parse({"_UID": "x"})
        assert row["uid"] is None


class _IdentityParser:
    def parse(self, event: dict) -> dict:
        return event


class TestJsonLineStreamSource:
    def test_yields_parsed_rows_until_stream_ends(self):
        # A short-lived command that emits ndjson then exits; the source
        # should yield one row per valid line and skip blank/garbage.
        script = "print('{\"n\": 1}'); print(''); print('garbage'); print('{\"n\": 2}')"
        source = JsonLineStreamSource([sys.executable, "-c", script], _IdentityParser())
        rows = list(source.stream(threading.Event()))
        assert rows == [{"n": 1}, {"n": 2}]

    def test_stop_event_set_before_start_yields_nothing_or_stops_early(self):
        stop = threading.Event()
        stop.set()
        script = "import time; print('{\"n\": 1}'); time.sleep(5)"
        source = JsonLineStreamSource([sys.executable, "-c", script], _IdentityParser())
        # Should terminate promptly rather than hang for 5s.
        rows = list(source.stream(stop))
        assert rows == [] or rows == [{"n": 1}]
