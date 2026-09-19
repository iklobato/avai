"""Streaming collectors: auth events and process execs, tailed from the OS log."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone

from .. import constants, slices
from ..constants import (
    AUTH_LOG_PREDICATE,
)
from ..runtime import (
    HostPaths,
    JsonLineStreamSource,
)
from .base import StreamingCollector


class UnifiedLogAuthParser:
    """Strategy: macOS ``log stream --style ndjson`` event → auth row."""

    def parse(self, event: dict) -> dict:
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

    slice = slices.AUTH_EVENTS
    judge_enabled = True
    judge_fields = ("process", "subsystem", "event_message")

    def __init__(self, predicate: str = AUTH_LOG_PREDICATE, judge_hints: str = ""):
        super().__init__(judge_hints=judge_hints)
        self.predicate = predicate

    def stream(self, stop_event: threading.Event):
        cmd = [
            "log",
            "stream",
            "--style",
            "ndjson",
            "--info",
            "--predicate",
            self.predicate,
        ]
        source = JsonLineStreamSource(
            cmd, UnifiedLogAuthParser(), killer_name="log-stream-killer"
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

    slice = slices.AUTH_EVENTS
    judge_enabled = True
    judge_fields = ("process", "subsystem", "event_message")

    _MATCH_GROUPS = [
        ["SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"],  # auth + authpriv
        ["_SYSTEMD_UNIT=sshd.service"],
        ["_SYSTEMD_UNIT=systemd-logind.service"],
        ["_COMM=sudo"],
        ["_COMM=su"],
        ["_COMM=polkitd"],
        ["_COMM=login"],
    ]

    def __init__(self, judge_hints: str = "", priority: str = "info"):
        super().__init__(judge_hints=judge_hints)
        self.priority = priority

    def _cmd(self) -> list[str]:
        cmd = [
            "journalctl",
            "-f",
            "--output=json",
            "--no-pager",
            f"--priority={self.priority}",
        ]
        # In container mode, point journalctl at the host's journal
        # directory rather than the container's empty one. Prefer the
        # persistent journal, but fall back to the runtime (volatile)
        # journal — hosts with systemd Storage=volatile/auto and no
        # persistent storage keep logs only under /run/log/journal, so
        # without this fallback auth_events would silently collect nothing.
        if constants.HOST_PREFIX:
            for host_journal in (
                HostPaths.translate("/var/log/journal"),
                HostPaths.translate("/run/log/journal"),
            ):
                if host_journal.is_dir():
                    cmd.extend(["--directory", str(host_journal)])
                    break
        for i, group in enumerate(self._MATCH_GROUPS):
            if i > 0:
                cmd.append("+")
            cmd.extend(group)
        return cmd

    def stream(self, stop_event: threading.Event):
        source = JsonLineStreamSource(
            self._cmd(), JournalAuthParser(), killer_name="journalctl-killer"
        )
        yield from source.stream(stop_event)


class JournalAuthParser:
    """Strategy: ``journalctl --output=json`` event → auth row."""

    def parse(self, event: dict) -> dict:
        # journalctl --output=json gives __REALTIME_TIMESTAMP in
        # microseconds since the epoch (as a string).
        ts_us = event.get("__REALTIME_TIMESTAMP")
        ts = None
        if ts_us:
            try:
                ts = datetime.fromtimestamp(
                    int(ts_us) / 1_000_000, tz=timezone.utc
                ).isoformat(timespec="seconds")
            except (TypeError, ValueError):
                pass

        try:
            pid = int(event["_PID"]) if event.get("_PID") else None
        except (TypeError, ValueError):
            pid = None

        return {
            "event_timestamp": ts,
            "process": event.get("_EXE") or event.get("_COMM"),
            "subsystem": event.get("_SYSTEMD_UNIT") or "syslog",
            "category": str(event.get("SYSLOG_FACILITY") or ""),
            "event_type": f"priority={event.get('PRIORITY', '?')}",
            "event_message": event.get("MESSAGE"),
            "pid": pid,
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

    slice = slices.PROCESS_EXEC_EVENTS
    judge_enabled = True
    judge_fields = ("exe_path", "exe_args_json", "uid", "parent_path")

    _EVENTS = ("exec",)

    def stream(self, stop_event: threading.Event):
        cmd = ["eslogger", *self._EVENTS]
        source = JsonLineStreamSource(
            cmd, EsloggerExecParser(), killer_name="eslogger-killer"
        )
        yield from source.stream(stop_event)


class EsloggerExecParser:
    """Strategy: macOS ``eslogger exec`` Endpoint-Security event → exec row."""

    def parse(self, event: dict) -> dict:
        # eslogger emits ES events: { time, action_type, event,
        # process, ... } where event.exec.{target, args, ...}
        event_obj = event.get("event") or {}
        exec_evt = event_obj.get("exec") or {}
        target = exec_evt.get("target") or {}
        target_exe = (target.get("executable") or {}).get("path")
        args = exec_evt.get("args") or []
        parent = event.get("process") or {}
        parent_path = (parent.get("executable") or {}).get("path")
        target_token = target.get("audit_token") or {}
        parent_token = parent.get("audit_token") or {}
        return {
            "event_timestamp": event.get("time"),
            "event_type": "exec",
            "pid": target_token.get("pid"),
            "ppid": parent_token.get("pid"),
            "uid": target_token.get("ruid"),
            "username": None,
            "exe_path": target_exe,
            "exe_args_json": json.dumps(args),
            "parent_path": parent_path,
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

    slice = slices.PROCESS_EXEC_EVENTS
    judge_enabled = True
    judge_fields = ("exe_path", "exe_args_json", "uid", "parent_path")

    def _cmd(self) -> list[str]:
        cmd = ["journalctl", "-f", "--output=json", "--no-pager"]
        if constants.HOST_PREFIX:
            host_journal = HostPaths.translate("/var/log/journal")
            if host_journal.is_dir():
                cmd.extend(["--directory", str(host_journal)])
        cmd.extend(["_AUDIT_TYPE_NAME=EXECVE", "+", "_AUDIT_TYPE_NAME=SYSCALL"])
        return cmd

    def stream(self, stop_event: threading.Event):
        source = JsonLineStreamSource(
            self._cmd(), AuditExecParser(), killer_name="journalctl-audit-killer"
        )
        yield from source.stream(stop_event)


class AuditExecParser:
    """Strategy: Linux audit ``journalctl --output=json`` event → exec row."""

    def parse(self, event: dict) -> dict:
        ts_us = event.get("__REALTIME_TIMESTAMP")
        ts = None
        if ts_us:
            try:
                ts = datetime.fromtimestamp(
                    int(ts_us) / 1_000_000, tz=timezone.utc
                ).isoformat(timespec="seconds")
            except (TypeError, ValueError):
                pass
        try:
            pid = int(event["_PID"]) if event.get("_PID") else None
        except (TypeError, ValueError):
            pid = None
        try:
            uid = int(event["_UID"]) if event.get("_UID") else None
        except (TypeError, ValueError):
            uid = None
        # audit EXECVE messages carry the args as separate fields a0,
        # a1, ... in the structured message; SYSCALL records have
        # the exe= path and comm= name. The combined-record view is
        # typically captured under MESSAGE; we surface what's
        # available and dump the full event into raw_json so the
        # judge sees everything.
        return {
            "event_timestamp": ts,
            "event_type": event.get("_AUDIT_TYPE_NAME") or "AUDIT",
            "pid": pid,
            "ppid": None,
            "uid": uid,
            "username": None,
            "exe_path": event.get("EXE") or event.get("_EXE"),
            "exe_args_json": None,
            "parent_path": None,
            "signing_id": None,
            "raw_json": json.dumps(event),
        }
