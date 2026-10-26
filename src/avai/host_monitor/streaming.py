"""Background worker that drives one StreamingCollector in a thread."""

from __future__ import annotations

import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from .collectors import StreamingCollector
from .constants import STREAM_HEALTHY_RESET_S
from .runtime import Clock, Digest
from .sink import Sink
from .supervision import (
    BackoffPolicy,
    Completed,
    Crashed,
    ExponentialBackoff,
    InterruptibleSleep,
    LoggingSupervisionListener,
    Sleeper,
    Stopped,
    StreamOutcome,
    SupervisionListener,
)

# What a live stream can raise: tool and pipe errors, parse errors on a bad
# event, and database errors while writing. Each ends the session as Crashed
# so the worker restarts it instead of dying.
STREAM_FAILURES = (
    OSError,
    RuntimeError,
    ValueError,
    LookupError,
    TypeError,
    AttributeError,
    SQLAlchemyError,
)
WRITE_FAILURES = (SQLAlchemyError, OSError, ValueError, TypeError)


@dataclass(frozen=True)
class SupervisionPolicy:
    """How a streaming worker buffers, restarts and reports. Tests pass
    deterministic fakes for backoff and listener."""

    listener: SupervisionListener
    batch_size: int = 50
    flush_interval_s: float = 5.0
    join_timeout_s: float = 5.0
    healthy_reset_s: float = STREAM_HEALTHY_RESET_S
    backoff: BackoffPolicy = field(default_factory=ExponentialBackoff.standard)

    @classmethod
    def standard(cls, logger: logging.Logger) -> SupervisionPolicy:
        return cls(LoggingSupervisionListener(logger))


@dataclass(frozen=True)
class StreamChannel:
    """Where a worker's rows go."""

    sink: Sink
    hostname: str


@dataclass(frozen=True)
class WorkerControls:
    """A worker's policy plus the stop event its sleeper waits on."""

    policy: SupervisionPolicy
    stop_event: threading.Event
    sleeper: Sleeper

    @classmethod
    def interruptible(cls, policy: SupervisionPolicy) -> WorkerControls:
        # The sleeper wakes on this worker's own stop event, so a pending
        # backoff aborts the moment shutdown is requested.
        stop_event = threading.Event()
        return cls(policy, stop_event, InterruptibleSleep(stop_event))


class StreamingSupervisor:
    """Starts one worker per streaming collector at boot and joins them all on
    shutdown."""

    def __init__(
        self,
        sink: Sink,
        collectors: list[StreamingCollector],
        policy: SupervisionPolicy,
    ) -> None:
        self._sink = sink
        self._collectors = collectors
        self._policy = policy
        self._workers: list[StreamingWorker] = []

    def start(self) -> None:
        if not self._collectors:
            return
        channel = StreamChannel(self._sink, socket.gethostname())
        for collector in self._collectors:
            worker = StreamingWorker.create(collector, channel, self._policy)
            worker.start()
            self._workers.append(worker)
        self._policy.listener.report_pool("started", len(self._workers))

    def stop(self) -> None:
        for worker in self._workers:
            worker.stop()
        if self._workers:
            self._policy.listener.report_pool("stopped", len(self._workers))
        self._workers.clear()


class StreamingWorker:
    """Long-lived, self-healing execution policy for a
    :class:`StreamingCollector`.

    Owns one OS thread and a small write buffer. Buffered rows are flushed
    when the buffer reaches ``batch_size`` *or* ``flush_interval_s`` has
    elapsed since the last flush, whichever comes first. Each streaming
    session gets its own ``StreamingSession`` row (its ``run_id``).

    If the collector raises mid-stream, the worker does not die: it opens a
    fresh session and restarts, backing off between attempts. Restart
    timing, waiting, and crash escalation are delegated to injected
    collaborators (see :mod:`.supervision`). ``stop()`` signals the
    collector to terminate its source, aborts any pending backoff, and joins
    the thread.
    """

    def __init__(
        self,
        collector: StreamingCollector,
        channel: StreamChannel,
        controls: WorkerControls,
    ) -> None:
        self.collector = collector
        self._channel = channel
        self._controls = controls
        self.thread: threading.Thread | None = None
        self.run_id: str | None = None
        self._rows_written = 0
        self._restart_attempt = 0

    @classmethod
    def create(
        cls,
        collector: StreamingCollector,
        channel: StreamChannel,
        policy: SupervisionPolicy,
    ) -> StreamingWorker:
        return cls(collector, channel, WorkerControls.interruptible(policy))

    @property
    def stop_event(self) -> threading.Event:
        return self._controls.stop_event

    @property
    def _policy(self) -> SupervisionPolicy:
        return self._controls.policy

    def start(self) -> None:
        if self.thread is not None and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self._run,
            name=f"stream-{self.collector.name}",
            daemon=True,
        )
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=self._policy.join_timeout_s)

    def _run(self) -> None:
        """Supervision loop: run a session, then dispatch on its outcome.

        The loop owns only the restart attempt count (the backoff input) and
        the healthy-run reset; every other decision lives behind an injected
        collaborator.
        """
        self._restart_attempt = 0
        while not self.stop_event.is_set():
            started = time.monotonic()
            outcome = self._stream_once()
            self._note_runtime(time.monotonic() - started)
            if not outcome.accept(self):
                break

    def _note_runtime(self, elapsed_s: float) -> None:
        if elapsed_s < self._policy.healthy_reset_s:
            return
        if self._restart_attempt:
            self._policy.listener.report_healthy(self.collector.name)
        self._restart_attempt = 0

    # -- OutcomeHandler: one method per StreamOutcome, no status branching --

    def on_completed(self) -> bool:
        # A finite stream ran dry; nothing to restart.
        return False

    def on_stopped(self) -> bool:
        return False

    def on_crashed(self, exc: BaseException) -> bool:
        if self.stop_event.is_set():
            return False
        self._restart_attempt += 1
        self._policy.listener.report_crash(
            self.collector.name, self._restart_attempt, exc
        )
        delay = self._policy.backoff.delay_for(self._restart_attempt)
        self._controls.sleeper.sleep(delay)
        return not self.stop_event.is_set()

    def _stream_once(self) -> StreamOutcome:
        """Drive one streaming session to its end and classify how it ended.

        A clean return means the generator was exhausted (``Completed``) or
        shutdown was requested (``Stopped``); an escaped exception means the
        collector died (``Crashed``). The supervisor decides what each
        outcome warrants.
        """
        rows_before = self._rows_written
        self.run_id = self._channel.sink.start_streaming_session(
            self.collector.name, self._channel.hostname
        )
        self._policy.listener.report_session_start(self.collector.name, self.run_id)
        buffer: list[dict[str, Any]] = []
        try:
            crash = self._pump(buffer)
        finally:
            self._close_session(buffer, rows_before)
        return self._outcome(crash)

    def _pump(self, buffer: list[dict[str, Any]]) -> BaseException | None:
        last_flush = time.monotonic()
        try:
            for row in self.collector.stream(self.stop_event):
                buffer.append(self._stamped(row))
                last_flush = self._flush_if_due(buffer, last_flush)
        except STREAM_FAILURES as exc:  # relayed to the supervisor as Crashed
            return exc
        return None

    def _stamped(self, row: dict[str, Any]) -> dict[str, Any]:
        row["run_id"] = self.run_id
        row["collected_at"] = Clock().now_iso()
        row["content_hash"] = Digest().of_row(row, self.collector.judge_fields)
        return row

    def _flush_if_due(self, buffer: list[dict[str, Any]], last_flush: float) -> float:
        now = time.monotonic()
        full = len(buffer) >= self._policy.batch_size
        stale = bool(buffer) and now - last_flush >= self._policy.flush_interval_s
        if not (full or stale):
            return last_flush
        self._safe_flush(buffer)
        return now

    def _safe_flush(self, buffer: list[dict[str, Any]]) -> None:
        try:
            self._flush(buffer)
        except WRITE_FAILURES as exc:
            self._policy.listener.report_write_failure(self.collector.name, exc)

    def _flush(self, buffer: list[dict[str, Any]]) -> None:
        if not buffer:
            return
        self._channel.sink.write(self.collector.model, buffer)
        self._rows_written += len(buffer)
        buffer.clear()

    def _close_session(self, buffer: list[dict[str, Any]], rows_before: int) -> None:
        self._safe_flush(buffer)
        session_rows = self._rows_written - rows_before
        try:
            self._channel.sink.end_streaming_session(self.run_id, session_rows)
        except WRITE_FAILURES as exc:
            self._policy.listener.report_write_failure(self.collector.name, exc)
        self._policy.listener.report_session_end(self.collector.name, session_rows)

    def _outcome(self, crash: BaseException | None) -> StreamOutcome:
        if crash is not None:
            return Crashed(crash)
        if self.stop_event.is_set():
            return Stopped()
        return Completed()
