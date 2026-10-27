from __future__ import annotations

import json
import threading
from collections.abc import Iterator, Mapping
from datetime import datetime, timezone
from typing import Any

from ..slices import Slices
from ..constants import AUTH_LOG_PREDICATE
from ..runtime import HostPaths, JsonLineStreamSource
from .base import StreamingCollector

MICROSECONDS_PER_SECOND = 1_000_000
JOURNAL_PRIORITY = "info"
HOST_JOURNALS = ("/var/log/journal", "/run/log/journal")


class JournalEvent:
    """One ``journalctl --output=json`` event and its typed fields."""

    def __init__(self, event: Mapping[str, Any]) -> None:
        self._event = event

    def timestamp(self) -> str | None:
        """``__REALTIME_TIMESTAMP`` (microseconds since the epoch, as a
        string) as an ISO-8601 UTC timestamp."""
        raw = self._event.get("__REALTIME_TIMESTAMP")
        if not raw:
            return None
        try:
            seconds = int(raw) / MICROSECONDS_PER_SECOND
        except (TypeError, ValueError):
            return None
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat(
            timespec="seconds"
        )

    def int_field(self, name: str) -> int | None:
        try:
            return int(self._event[name]) if self._event.get(name) else None
        except (TypeError, ValueError):
            return None


class HostJournal:
    """Journal directory flags for journalctl in container mode."""

    def __init__(self, paths: HostPaths) -> None:
        self._paths = paths

    def directory_args(self, candidates: tuple[str, ...]) -> list[str]:
        """In container mode, point journalctl at the host's journal
        directory rather than the container's empty one: the first
        candidate that exists wins."""
        paths = self._paths
        if not paths.in_container():
            return []
        found = next(
            (path for path in map(paths.translate, candidates) if path.is_dir()), None
        )
        return ["--directory", str(found)] if found else []


class UnifiedLogAuthParser:
    """Strategy: macOS ``log stream --style ndjson`` event → auth row."""

    def parse(self, event: dict[str, Any]) -> dict[str, Any]:
        return {
            "event_timestamp": event.get("timestamp"),
            "process": event.get("processImagePath"),
            "subsystem": event.get("subsystem"),
            "category": event.get("category"),
            "event_type": event.get("eventType"),
            "event_message": event.get("eventMessage"),
            "pid": event.get("processID"),
            "raw_json": json.dumps(event),
        }


class AuthEventsCollector(StreamingCollector):
    """Tails the macOS unified log forever via ``log stream``. Each
    matching event is yielded as it arrives — no polling gaps."""

    slice = Slices.AUTH_EVENTS
    judge_enabled = True
    judge_fields = ("process", "subsystem", "event_message")
    predicate = AUTH_LOG_PREDICATE

    def stream(self, stop_event: threading.Event) -> Iterator[dict[str, Any]]:
        cmd = ["log", "stream", "--style", "ndjson", "--info"]
        source = JsonLineStreamSource(
            [*cmd, "--predicate", self.predicate],
            UnifiedLogAuthParser(),
            "log-stream-killer",
        )
        yield from source.stream(stop_event)


class LinuxAuthEventsCollector(StreamingCollector):
    """Linux equivalent of :class:`AuthEventsCollector` — tails
    ``journalctl -f --output=json`` filtered to security-relevant
    sources (auth+authpriv syslog facilities, sshd, systemd-logind,
    sudo, su, polkitd). Yields rows in the same shape as the macOS
    streaming collector so the dashboard treats them identically.

    The OR semantics across different journalctl matchers require
    inserting ``+`` between AND-groups; same-field matchers within a
    group OR by default.
    """

    slice = Slices.AUTH_EVENTS
    judge_enabled = True
    judge_fields = ("process", "subsystem", "event_message")

    MATCH_GROUPS = (
        ("SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"),  # auth + authpriv
        ("_SYSTEMD_UNIT=sshd.service",),
        ("_SYSTEMD_UNIT=systemd-logind.service",),
        ("_COMM=sudo",),
        ("_COMM=su",),
        ("_COMM=polkitd",),
        ("_COMM=login",),
    )

    def __init__(self, journal: HostJournal, judge_hints: str = "") -> None:
        super().__init__(judge_hints)
        self._journal = journal

    def command(self) -> list[str]:
        cmd = ["journalctl", "-f", "--output=json", "--no-pager"]
        cmd.append(f"--priority={JOURNAL_PRIORITY}")
        # Prefer the persistent journal, but fall back to the runtime
        # (volatile) journal — hosts with systemd Storage=volatile/auto and
        # no persistent storage keep logs only under /run/log/journal, so
        # without this fallback auth_events would silently collect nothing.
        cmd.extend(self._journal.directory_args(HOST_JOURNALS))
        cmd.extend(self._matchers())
        return cmd

    def stream(self, stop_event: threading.Event) -> Iterator[dict[str, Any]]:
        source = JsonLineStreamSource(
            self.command(), JournalAuthParser(), "journalctl-killer"
        )
        yield from source.stream(stop_event)

    def _matchers(self) -> list[str]:
        matchers: list[str] = []
        for group in self.MATCH_GROUPS:
            if matchers:
                matchers.append("+")
            matchers.extend(group)
        return matchers


class JournalAuthParser:
    """Strategy: ``journalctl --output=json`` event → auth row."""

    def parse(self, event: dict[str, Any]) -> dict[str, Any]:
        journal = JournalEvent(event)
        return {
            "event_timestamp": journal.timestamp(),
            "process": event.get("_EXE") or event.get("_COMM"),
            "subsystem": event.get("_SYSTEMD_UNIT") or "syslog",
            "category": str(event.get("SYSLOG_FACILITY") or ""),
            "event_type": f"priority={event.get('PRIORITY', '?')}",
            "event_message": event.get("MESSAGE"),
            "pid": journal.int_field("_PID"),
            "raw_json": json.dumps(event),
        }


class MacosProcessExecCollector(StreamingCollector):
    """Tails ``eslogger exec`` — Apple's Endpoint-Security CLI, shipped
    since macOS Ventura. Each ``exec(2)`` on the host emits one JSON
    object with the executing binary, args, parent, and signing
    information. Requires root (the binary itself enforces this).

    judge_enabled is True so the LLM evaluates each *unique*
    (exe_path, args, user, parent_path) combination — content_hash
    dedupe means a busy machine costs O(unique-binaries-run) LLM
    calls, not O(every-exec).
    """

    slice = Slices.PROCESS_EXEC_EVENTS
    judge_enabled = True
    judge_fields = ("exe_path", "exe_args_json", "uid", "parent_path")

    EVENTS = ("exec",)

    def stream(self, stop_event: threading.Event) -> Iterator[dict[str, Any]]:
        source = JsonLineStreamSource(
            ["eslogger", *self.EVENTS], EsloggerExecParser(), "eslogger-killer"
        )
        yield from source.stream(stop_event)


class EsloggerExecParser:
    """Strategy: macOS ``eslogger exec`` Endpoint-Security event → exec row.

    eslogger emits ES events: { time, action_type, event, process, ... }
    where event.exec.{target, args, ...}."""

    def parse(self, event: dict[str, Any]) -> dict[str, Any]:
        exec_event = (event.get("event") or {}).get("exec") or {}
        target = exec_event.get("target") or {}
        parent = event.get("process") or {}
        target_token = target.get("audit_token") or {}
        return {
            "event_timestamp": event.get("time"),
            "event_type": "exec",
            "pid": target_token.get("pid"),
            "ppid": (parent.get("audit_token") or {}).get("pid"),
            "uid": target_token.get("ruid"),
            "username": None,
            "exe_path": (target.get("executable") or {}).get("path"),
            "exe_args_json": json.dumps(exec_event.get("args") or []),
            "parent_path": (parent.get("executable") or {}).get("path"),
            "signing_id": target.get("signing_id"),
            "raw_json": json.dumps(event),
        }


class LinuxProcessExecCollector(StreamingCollector):
    """Tails the Linux audit subsystem for ``execve`` events via
    ``journalctl -f --output=json`` matchers on the audit type names.

    Requires ``auditd`` running on the host with the execve rule
    installed, e.g.::

        auditctl -a always,exit -F arch=b64 -S execve

    (most distros ship ``audit`` enabled by default for SECCOMP /
    PAM events; the execve rule is the additional configuration.)
    """

    slice = Slices.PROCESS_EXEC_EVENTS
    judge_enabled = True
    judge_fields = ("exe_path", "exe_args_json", "uid", "parent_path")

    def __init__(self, journal: HostJournal, judge_hints: str = "") -> None:
        super().__init__(judge_hints)
        self._journal = journal

    def command(self) -> list[str]:
        cmd = ["journalctl", "-f", "--output=json", "--no-pager"]
        cmd.extend(self._journal.directory_args(HOST_JOURNALS[:1]))
        cmd.extend(["_AUDIT_TYPE_NAME=EXECVE", "+", "_AUDIT_TYPE_NAME=SYSCALL"])
        return cmd

    def stream(self, stop_event: threading.Event) -> Iterator[dict[str, Any]]:
        source = JsonLineStreamSource(
            self.command(), AuditExecParser(), "journalctl-audit-killer"
        )
        yield from source.stream(stop_event)


class AuditExecParser:
    """Strategy: Linux audit ``journalctl --output=json`` event → exec row.

    Audit EXECVE messages carry the args as separate fields a0, a1, ... in
    the structured message; SYSCALL records have the exe= path and comm=
    name. The combined-record view is typically captured under MESSAGE; we
    surface what's available and dump the full event into raw_json so the
    judge sees everything."""

    def parse(self, event: dict[str, Any]) -> dict[str, Any]:
        journal = JournalEvent(event)
        return {
            "event_timestamp": journal.timestamp(),
            "event_type": event.get("_AUDIT_TYPE_NAME") or "AUDIT",
            "pid": journal.int_field("_PID"),
            "ppid": None,
            "uid": journal.int_field("_UID"),
            "username": None,
            "exe_path": event.get("EXE") or event.get("_EXE"),
            "exe_args_json": None,
            "parent_path": None,
            "signing_id": None,
            "raw_json": json.dumps(event),
        }
