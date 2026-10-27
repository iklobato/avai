"""The cooperative control plane: the dashboard writes intent to the control
row (see models.ControlState) and the monitor reads it, obeys, and writes
its heartbeat back. There is no other IPC."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .constants import MONITOR_PROGRESS_HEARTBEAT_S
from .enums import MaintenanceCommand, MonitorState
from .failures import HOST_FAILURES
from .runtime import Clock, HostIdentity
from .sink import Sink


@dataclass(frozen=True)
class ControlDefaults:
    """How the monitor was started; used while the control row leaves a
    setting unset."""

    judge: bool
    enrich: bool


@dataclass(frozen=True)
class CycleSettings:
    """The control row as read at one moment, read as effective settings.
    A None column means "unset", which falls back to the defaults."""

    row: dict[str, Any]
    defaults: ControlDefaults

    def disabled_collectors(self) -> set[str]:
        raw = self.row.get("disabled_collectors")
        if not raw:
            return set()
        return {name.strip() for name in raw.split(",") if name.strip()}

    def judge_on(self) -> bool:
        value = self.row.get("judge_enabled")
        return self.defaults.judge if value is None else bool(value)

    def enrich_on(self) -> bool:
        value = self.row.get("enrich_enabled")
        return self.defaults.enrich if value is None else bool(value)


class ControlSettings:
    """Reads the control row the dashboard writes."""

    def __init__(self, sink: Sink, defaults: ControlDefaults) -> None:
        self._sink = sink
        self._defaults = defaults

    def current(self) -> CycleSettings:
        return CycleSettings(self._sink.read_control() or {}, self._defaults)


class ProgressHeartbeat:
    """Refreshes last_seen_at mid-scan so a long cycle doesn't read as
    offline on the dashboard. Throttled to one write per
    MONITOR_PROGRESS_HEARTBEAT_S, so it is cheap to call in tight
    collector/enrichment loops. The control loop owns status/interval, so
    this touches only the timestamp."""

    def __init__(self, sink: Sink, logger: logging.Logger, clock: Clock) -> None:
        self._sink = sink
        self._logger = logger
        self._clock = clock
        self._last_beat = 0.0

    def reset(self) -> None:
        # The control loop wrote a full heartbeat just before the cycle, so
        # the first touch lands one interval into the scan, not immediately.
        self._last_beat = self._clock.monotonic()

    def beat(self) -> None:
        now = self._clock.monotonic()
        if now - self._last_beat < MONITOR_PROGRESS_HEARTBEAT_S:
            return
        self._last_beat = now
        try:
            self._sink.touch_heartbeat()
        except HOST_FAILURES:
            self._logger.exception("progress heartbeat write failed")


class Maintenance:
    """Runs one-shot maintenance commands and returns the short result the
    dashboard shows."""

    def __init__(self, sink: Sink, max_db_bytes: int) -> None:
        self._sink = sink
        self._max_db_bytes = max_db_bytes

    def apply(self, command: MaintenanceCommand) -> str:
        actions: dict[MaintenanceCommand, Callable[[], str]] = {
            MaintenanceCommand.PRUNE: self._prune,
            MaintenanceCommand.CLEAR: self._clear,
            MaintenanceCommand.REJUDGE: self._rejudge,
            MaintenanceCommand.RENARRATE: self._renarrate,
            MaintenanceCommand.RESET_BASELINE: self._reset_baseline,
        }
        return actions[command]()

    def _prune(self) -> str:
        stats = self._sink.prune_to_size(self._max_db_bytes)
        return f"pruned runs={stats['runs_pruned']} events={stats['events_pruned']}"

    def _clear(self) -> str:
        return f"cleared {self._sink.clear_data()} rows"

    def _rejudge(self) -> str:
        return f"cleared {self._sink.clear_judgements()} judgements"

    def _renarrate(self) -> str:
        return f"cleared {self._sink.clear_narratives()} narratives"

    def _reset_baseline(self) -> str:
        return f"reset baseline ({self._sink.reset_baseline()} runs dropped)"


@dataclass(frozen=True)
class ControlPlane:
    """What the control loop reads and writes through, and how it stops."""

    sink: Sink
    shutdown_event: threading.Event
    logger: logging.Logger
    max_db_bytes: int = 0
    clock: Clock = field(default_factory=Clock)
    identity: HostIdentity = field(default_factory=HostIdentity.current)


class ControlLoop:
    """The daemon loop: polls the control row, runs one-shot maintenance
    commands, and runs a cycle when the interval elapses or the dashboard
    asks for a scan now."""

    # Bounds the latency of pause / resume / scan-now / maintenance commands
    # (the dashboard can't signal us directly, only through the shared DB).
    POLL_SECONDS = 3.0
    ERROR_EXCERPT_CHARS = 120

    def __init__(
        self,
        plane: ControlPlane,
        settings: ControlSettings,
        run_cycle: Callable[[], tuple[str, int, int]],
    ) -> None:
        self._plane = plane
        self._settings = settings
        self._run_cycle = run_cycle

    def run_forever(self, interval: int) -> None:
        # Scan immediately on the first tick, then every effective interval.
        next_scan = self._plane.clock.monotonic()
        while not self._plane.shutdown_event.is_set():
            next_scan = self._tick(interval, next_scan)
            # Backed by the shutdown event so SIGINT/SIGTERM stay responsive
            # within one poll interval.
            self._plane.shutdown_event.wait(timeout=self.POLL_SECONDS)

    def _tick(self, interval: int, next_scan: float) -> float:
        """Handle one poll and return when the next scheduled scan is due."""
        control = self._settings.current().row
        self._run_pending_command(control)  # one-shot maintenance, even if paused
        effective = control.get("interval_override") or interval
        paused = bool(control.get("paused"))
        scan_now = control.get("scan_now_nonce", 0) != control.get(
            "scan_now_applied", 0
        )
        if not scan_now and (paused or self._plane.clock.monotonic() < next_scan):
            state = MonitorState.PAUSED if paused else MonitorState.RUNNING
            self._heartbeat(state, effective)
            return next_scan
        if scan_now:
            # Scan-now runs one cycle even while paused.
            self._plane.sink.ack_scan_now(control["scan_now_nonce"])
        self._heartbeat(MonitorState.SCANNING, effective)
        started = self._plane.clock.monotonic()
        self._cycle_or_log()
        return started + effective

    def _cycle_or_log(self) -> None:
        try:
            run_id, ok, failed = self._run_cycle()
        except HOST_FAILURES:
            self._plane.logger.exception("run failed")
            return
        self._plane.logger.info(
            "run complete run_id=%s ok=%d failed=%d", run_id, ok, failed
        )

    def _run_pending_command(self, control: dict[str, Any]) -> None:
        """Execute a maintenance command if a new nonce is present, then
        acknowledge it. A failed command must not kill the loop."""
        nonce = control.get("command_nonce", 0)
        if nonce == control.get("command_applied", 0):
            return
        raw = control.get("command")
        try:
            outcome = self._execute(raw)
        except HOST_FAILURES as exc:  # reported back to the dashboard
            self._plane.logger.exception("control command %s failed", raw)
            excerpt = str(exc)[: self.ERROR_EXCERPT_CHARS]
            outcome = f"error: {type(exc).__name__}: {excerpt}"
        self._plane.sink.ack_command(nonce, outcome)
        self._plane.logger.info("control command applied: %s -> %s", raw, outcome)

    def _execute(self, raw: str | None) -> str:
        try:
            command = MaintenanceCommand(raw)
        except ValueError:
            return f"unknown command: {raw}"
        return Maintenance(self._plane.sink, self._plane.max_db_bytes).apply(command)

    def _heartbeat(self, status: MonitorState, current_interval: int) -> None:
        try:
            self._plane.sink.write_heartbeat(
                pid=self._plane.identity.pid,
                status=status.value,
                current_interval=current_interval,
            )
        except HOST_FAILURES:
            self._plane.logger.exception("heartbeat write failed")
