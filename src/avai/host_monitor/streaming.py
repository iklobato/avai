"""Background worker that drives one StreamingCollector in a thread."""

from __future__ import annotations

import threading
import time
from typing import Optional

from .collectors import StreamingCollector
from .constants import LOG, STREAM_HEALTHY_RESET_S
from .runtime import Clock, Digest
from .sink import Sink
from .supervision import (
    BackoffPolicy,
    Completed,
    Crashed,
    InterruptibleSleep,
    LoggingSupervisionListener,
    Sleeper,
    Stopped,
    StreamOutcome,
    SupervisionListener,
    default_backoff,
)


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
    collaborators (see :mod:`.supervision`) so the policy is configurable
    and the behaviour is deterministically testable. ``stop()`` signals the
    collector to terminate its source, aborts any pending backoff, and joins
    the thread.
    """

    def __init__(
        self,
        collector: StreamingCollector,
        sink: Sink,
        hostname: str,
        batch_size: int = 50,
        flush_interval_s: float = 5.0,
        join_timeout_s: float = 5.0,
        backoff: Optional[BackoffPolicy] = None,
        sleeper: Optional[Sleeper] = None,
        listener: Optional[SupervisionListener] = None,
        healthy_reset_s: float = STREAM_HEALTHY_RESET_S,
    ):
        self.collector = collector
        self.sink = sink
        self.hostname = hostname
        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s
        self.join_timeout_s = join_timeout_s
        self.healthy_reset_s = healthy_reset_s
        self.stop_event = threading.Event()
        # Production defaults wired here so callers get supervision for free;
        # tests inject deterministic fakes (immediate sleeper, recording
        # listener/backoff) through the same parameters.
        self.backoff = backoff or default_backoff()
        self.sleeper = sleeper or InterruptibleSleep(self.stop_event)
        self.listener = listener or LoggingSupervisionListener()
        self.thread: Optional[threading.Thread] = None
        self.run_id: Optional[str] = None
        self._rows_written = 0
        self._restart_attempt = 0

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
            self.thread.join(timeout=self.join_timeout_s)

    def _flush(self, buffer: list[dict]) -> None:
        if not buffer:
            return
        self.sink.write(self.collector.model, buffer)
        self._rows_written += len(buffer)
        buffer.clear()

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
            if time.monotonic() - started >= self.healthy_reset_s:
                if self._restart_attempt:
                    self.listener.report_healthy(self.collector.name)
                self._restart_attempt = 0
            if not outcome.accept(self):
                break

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
        self.listener.report_crash(self.collector.name, self._restart_attempt, exc)
        self.sleeper.sleep(self.backoff.delay_for(self._restart_attempt))
        return not self.stop_event.is_set()

    def _stream_once(self) -> StreamOutcome:
        """Drive one streaming session to its end and classify how it ended.

        A clean return means the generator was exhausted (``Completed``) or
        shutdown was requested (``Stopped``); an escaped exception means the
        collector died (``Crashed``). The supervisor decides what each
        outcome warrants.
        """
        rows_before = self._rows_written
        self.run_id = self.sink.start_streaming_session(
            self.collector.name,
            self.hostname,
        )
        LOG.info(
            "streaming collector=%s run_id=%s started", self.collector.name, self.run_id
        )
        buffer: list[dict] = []
        last_flush = time.monotonic()
        crash: Optional[BaseException] = None
        try:
            for row in self.collector.stream(self.stop_event):
                row["run_id"] = self.run_id
                row["collected_at"] = Clock().now_iso()
                row["content_hash"] = Digest.of_row(row, self.collector.judge_fields)
                buffer.append(row)
                now = time.monotonic()
                if len(buffer) >= self.batch_size or (
                    buffer and now - last_flush >= self.flush_interval_s
                ):
                    try:
                        self._flush(buffer)
                    except Exception:
                        LOG.exception(
                            "streaming flush failed collector=%s", self.collector.name
                        )
                    last_flush = now
        except Exception as exc:  # noqa: BLE001 - relayed to the supervisor as Crashed
            crash = exc
        finally:
            try:
                self._flush(buffer)
            except Exception:
                LOG.exception(
                    "streaming final flush failed collector=%s", self.collector.name
                )
            session_rows = self._rows_written - rows_before
            try:
                self.sink.end_streaming_session(self.run_id, session_rows)
            except Exception:
                LOG.exception(
                    "end_streaming_session failed collector=%s", self.collector.name
                )
            self.listener.report_session_end(self.collector.name, session_rows)
        if crash is not None:
            return Crashed(crash)
        if self.stop_event.is_set():
            return Stopped()
        return Completed()
