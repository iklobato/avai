"""The cooperative control plane: the dashboard writes intent to the control
row (see models.ControlState) and the monitor reads it, obeys, and writes
its heartbeat back. There is no other IPC."""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from enum import StrEnum

from .constants import LOG, MONITOR_PROGRESS_HEARTBEAT_S
from .sink import Sink


class ControlSettings:
    """The control row cached once per cycle, read as effective settings.
    A None column means "unset", which falls back to how the monitor was
    started."""

    def __init__(self, sink: Sink, judge_default: bool, enrich_default: bool):
        self._sink = sink
        self._judge_default = judge_default
        self._enrich_default = enrich_default
        self._row: dict = {}

    def refresh(self) -> dict:
        self._row = self._sink.read_control() or {}
        return self._row

    def disabled_collectors(self) -> set[str]:
        raw = self._row.get("disabled_collectors")
        return {s.strip() for s in raw.split(",") if s.strip()} if raw else set()

    def judge_on(self) -> bool:
        value = self._row.get("judge_enabled")
        return self._judge_default if value is None else bool(value)

    def enrich_on(self) -> bool:
        value = self._row.get("enrich_enabled")
        return self._enrich_default if value is None else bool(value)


class ProgressHeartbeat:
    """Refreshes last_seen_at mid-scan so a long cycle doesn't read as
    offline on the dashboard. Throttled to one write per
    MONITOR_PROGRESS_HEARTBEAT_S, so it is cheap to call in tight
    collector/enrichment loops. The control loop owns status/interval, so
    this touches only the timestamp."""

    def __init__(self, sink: Sink):
        self._sink = sink
        self._last_beat = 0.0

    def reset(self) -> None:
        # The control loop wrote a full heartbeat just before the cycle, so
        # the first touch lands one interval into the scan, not immediately.
        self._last_beat = time.monotonic()

    def beat(self) -> None:
        now = time.monotonic()
        if now - self._last_beat < MONITOR_PROGRESS_HEARTBEAT_S:
            return
        self._last_beat = now
        try:
            self._sink.touch_heartbeat()
        except Exception:
            LOG.exception("progress heartbeat write failed")


class MaintenanceCommand(StrEnum):
    PRUNE = "prune"
    CLEAR = "clear"
    REJUDGE = "rejudge"
    RENARRATE = "renarrate"
    RESET_BASELINE = "reset_baseline"

    def apply(self, sink: Sink, max_db_bytes: int) -> str:
        """Run the command and return the short result the dashboard shows."""
        return _COMMAND_ACTIONS[self](sink, max_db_bytes)


def _prune(sink: Sink, max_db_bytes: int) -> str:
    stats = sink.prune_to_size(max_db_bytes)
    return f"pruned runs={stats['runs_pruned']} events={stats['events_pruned']}"


def _clear(sink: Sink, _max_db_bytes: int) -> str:
    return f"cleared {sink.clear_data()} rows"


def _rejudge(sink: Sink, _max_db_bytes: int) -> str:
    return f"cleared {sink.clear_judgements()} judgements"


def _renarrate(sink: Sink, _max_db_bytes: int) -> str:
    return f"cleared {sink.clear_narratives()} narratives"


def _reset_baseline(sink: Sink, _max_db_bytes: int) -> str:
    return f"reset baseline ({sink.reset_baseline()} runs dropped)"


_COMMAND_ACTIONS: dict[MaintenanceCommand, Callable[[Sink, int], str]] = {
    MaintenanceCommand.PRUNE: _prune,
    MaintenanceCommand.CLEAR: _clear,
    MaintenanceCommand.REJUDGE: _rejudge,
    MaintenanceCommand.RENARRATE: _renarrate,
    MaintenanceCommand.RESET_BASELINE: _reset_baseline,
}


class ControlLoop:
    """The daemon loop: polls the control row, runs one-shot maintenance
    commands, and runs a cycle when the interval elapses or the dashboard
    asks for a scan now."""

    # Bounds the latency of pause / resume / scan-now / maintenance commands
    # (the dashboard can't signal us directly, only through the shared DB).
    POLL_SECONDS = 3.0

    def __init__(
        self,
        sink: Sink,
        settings: ControlSettings,
        run_cycle: Callable[[], tuple[str, int, int]],
        max_db_bytes: int,
        shutdown_event: threading.Event,
    ):
        self._sink = sink
        self._settings = settings
        self._run_cycle = run_cycle
        self._max_db_bytes = max_db_bytes
        self._shutdown = shutdown_event

    def run_forever(self, interval: int) -> None:
        # Scan immediately on the first tick, then every effective interval.
        next_scan = time.monotonic()
        while not self._shutdown.is_set():
            ctrl = self._settings.refresh()
            self._run_pending_command(ctrl)  # one-shot maintenance, even if paused
            effective = ctrl.get("interval_override") or interval
            paused = bool(ctrl.get("paused"))
            scan_now = ctrl.get("scan_now_nonce", 0) != ctrl.get("scan_now_applied", 0)

            if scan_now or (time.monotonic() >= next_scan and not paused):
                if scan_now:
                    # Scan-now runs one cycle even while paused.
                    self._sink.ack_scan_now(ctrl["scan_now_nonce"])
                self._heartbeat("scanning", effective)
                started = time.monotonic()
                self._cycle_or_log()
                next_scan = started + effective
            else:
                self._heartbeat("paused" if paused else "running", effective)

            # Backed by the shutdown event so SIGINT/SIGTERM stay responsive
            # within one poll interval.
            self._shutdown.wait(timeout=self.POLL_SECONDS)

    def _cycle_or_log(self) -> None:
        try:
            run_id, ok, failed = self._run_cycle()
        except Exception:
            LOG.exception("run failed")
            return
        LOG.info("run complete run_id=%s ok=%d failed=%d", run_id, ok, failed)

    def _run_pending_command(self, ctrl: dict) -> None:
        """Execute a maintenance command if a new nonce is present, then
        acknowledge it. A failed command must not kill the loop."""
        nonce = ctrl.get("command_nonce", 0)
        if nonce == ctrl.get("command_applied", 0):
            return
        raw = ctrl.get("command")
        try:
            result = self._execute(raw)
        except Exception as exc:  # noqa: BLE001 - reported back to the dashboard
            LOG.exception("control command %s failed", raw)
            result = f"error: {type(exc).__name__}: {str(exc)[:120]}"
        self._sink.ack_command(nonce, result)
        LOG.info("control command applied: %s -> %s", raw, result)

    def _execute(self, raw) -> str:
        try:
            command = MaintenanceCommand(raw)
        except ValueError:
            return f"unknown command: {raw}"
        return command.apply(self._sink, self._max_db_bytes)

    def _heartbeat(self, status: str, current_interval: int) -> None:
        try:
            self._sink.write_heartbeat(
                pid=os.getpid(), status=status, current_interval=current_interval
            )
        except Exception:
            LOG.exception("heartbeat write failed")
