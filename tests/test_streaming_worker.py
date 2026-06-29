"""Tests for ``StreamingWorker`` — long-lived background thread that
flushes rows to a Sink in batches.

These exercise the worker's lifecycle and buffering behaviour with
a synthetic streaming collector — no journalctl / eslogger needed.
"""

from __future__ import annotations

import logging
import threading
import time

import pytest
from sqlalchemy import create_engine

from avai.host_monitor import AuthEventRow, Sink, StreamingWorker
from avai.host_monitor.supervision import ExponentialBackoff, LoggingSupervisionListener


class _PausableStreamCollector:
    """Implements the StreamingCollector contract without inheriting
    from the ABC (avoiding model-validation cruft we don't need)."""

    name = "auth_events"
    model = AuthEventRow
    judge_enabled = False
    judge_fields = ("action", "user")
    judge_hints = ""

    def __init__(self, rows: list[dict], pause_after: int = 0):
        self._rows = rows
        self._pause_after = pause_after
        self.observed_stop = threading.Event()

    def stream(self, stop_event: threading.Event):
        for i, row in enumerate(self._rows):
            if stop_event.is_set():
                self.observed_stop.set()
                return
            yield row
            if self._pause_after and i + 1 >= self._pause_after:
                # Hold here until told to stop.
                while not stop_event.is_set():
                    time.sleep(0.01)
                self.observed_stop.set()
                return


@pytest.fixture
def sink(tmp_path):
    # File-based SQLite — required because StreamingWorker runs in a
    # background thread that opens its own connection, and ``:memory:``
    # DBs are private per-connection.
    db = tmp_path / "stream.db"
    engine = create_engine(f"sqlite:///{db}", connect_args={"check_same_thread": False})
    s = Sink(engine)
    s.setup()
    return s


def _make_row(action="login_ok", user="alice"):
    return {
        "timestamp": "2026-05-28T00:00:00+00:00",
        "facility": "auth",
        "host": "h",
        "process": "sshd",
        "pid": 1,
        "message": "x",
        "action": action,
        "user": user,
    }


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    def test_start_creates_thread(self, sink):
        c = _PausableStreamCollector([], pause_after=1)
        # Need at least one row so stream() blocks rather than returning
        # immediately.
        c._rows = [_make_row()]
        w = StreamingWorker(c, sink, "h")
        w.start()
        assert w.thread is not None
        assert w.thread.is_alive()
        w.stop()
        assert not w.thread.is_alive()

    def test_double_start_is_idempotent(self, sink):
        c = _PausableStreamCollector([_make_row()], pause_after=1)
        w = StreamingWorker(c, sink, "h")
        w.start()
        thread1 = w.thread
        w.start()  # no-op when thread alive
        assert w.thread is thread1
        w.stop()

    def test_stop_sets_stop_event(self, sink):
        c = _PausableStreamCollector([_make_row()], pause_after=1)
        w = StreamingWorker(c, sink, "h")
        w.start()
        w.stop()
        assert w.stop_event.is_set()
        assert c.observed_stop.is_set()

    def test_stop_without_start_is_safe(self, sink):
        c = _PausableStreamCollector([], pause_after=0)
        w = StreamingWorker(c, sink, "h")
        # No start() called — stop() should be a no-op, not crash.
        w.stop()


# ---------------------------------------------------------------------------
# Buffering and flushing
# ---------------------------------------------------------------------------


class TestFlushing:
    def test_flushes_full_batch(self, sink):
        rows = [_make_row(user=f"u{i}") for i in range(5)]
        c = _PausableStreamCollector(rows, pause_after=5)
        w = StreamingWorker(c, sink, "h", batch_size=5, flush_interval_s=99)
        w.start()
        # Wait for the worker to consume + flush.
        time.sleep(0.2)
        w.stop()

        from sqlalchemy import func, select
        from sqlalchemy.orm import Session

        with Session(sink.engine) as s:
            n = s.execute(select(func.count()).select_from(AuthEventRow)).scalar()
        assert n == 5
        assert w._rows_written == 5

    def test_flushes_on_interval_below_batch_size(self, sink):
        rows = [_make_row(user=f"u{i}") for i in range(2)]
        c = _PausableStreamCollector(rows, pause_after=2)
        # Big batch, fast interval → should flush by interval.
        w = StreamingWorker(c, sink, "h", batch_size=999, flush_interval_s=0.1)
        w.start()
        time.sleep(0.4)
        w.stop()
        # Both rows ended up flushed (either via interval or final flush).
        from sqlalchemy import func, select
        from sqlalchemy.orm import Session

        with Session(sink.engine) as s:
            n = s.execute(select(func.count()).select_from(AuthEventRow)).scalar()
        assert n == 2

    def test_final_flush_on_shutdown_drains_buffer(self, sink):
        # 3 rows, batch size 10 → buffer has 3 at stop time. The final
        # flush in the worker's `finally` should write them.
        rows = [_make_row(user=f"u{i}") for i in range(3)]
        c = _PausableStreamCollector(rows, pause_after=3)
        w = StreamingWorker(c, sink, "h", batch_size=100, flush_interval_s=99)
        w.start()
        time.sleep(0.2)
        w.stop()
        from sqlalchemy import func, select
        from sqlalchemy.orm import Session

        with Session(sink.engine) as s:
            n = s.execute(select(func.count()).select_from(AuthEventRow)).scalar()
        assert n == 3


# ---------------------------------------------------------------------------
# Supervision: deterministic fakes for the injected seams
# ---------------------------------------------------------------------------


class _ImmediateSleep:
    """Sleeper that records requested delays but never actually waits."""

    def __init__(self):
        self.waits: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.waits.append(seconds)


class _RecordingBackoff:
    """Backoff that records the attempt numbers it was asked about."""

    def __init__(self):
        self.attempts: list[int] = []

    def delay_for(self, attempt: int) -> float:
        self.attempts.append(attempt)
        return 0.0


class _RecordingListener:
    """Listener that records every callback and can halt a flapping worker
    once a crash reaches ``stop_at`` consecutive attempts."""

    def __init__(self, stop_at: int | None = None):
        self.crashes: list[int] = []
        self.healthy: int = 0
        self.session_ends: list[int] = []
        self.stop_at = stop_at
        self.stop_event: threading.Event | None = None

    def report_crash(self, collector, attempt, exc):
        self.crashes.append(attempt)
        if (
            self.stop_event is not None
            and self.stop_at is not None
            and attempt >= self.stop_at
        ):
            self.stop_event.set()

    def report_healthy(self, collector):
        self.healthy += 1

    def report_session_end(self, collector, rows):
        self.session_ends.append(rows)


def _row_count(sink) -> int:
    from sqlalchemy import func, select
    from sqlalchemy.orm import Session

    with Session(sink.engine) as s:
        return s.execute(select(func.count()).select_from(AuthEventRow)).scalar()


class _CrashOnceThenStream:
    """Crashes on its first session, then streams normally and blocks."""

    name = "auth_events"
    model = AuthEventRow
    judge_enabled = False
    judge_fields = ()
    judge_hints = ""

    def __init__(self):
        self.calls = 0

    def stream(self, stop_event):
        self.calls += 1
        yield _make_row()
        if self.calls == 1:
            raise RuntimeError("collector died")
        while not stop_event.is_set():
            time.sleep(0.01)


class _AlwaysCrash:
    """Yields one row then raises on every session."""

    name = "auth_events"
    model = AuthEventRow
    judge_enabled = False
    judge_fields = ()
    judge_hints = ""

    def stream(self, stop_event):
        yield _make_row()
        raise RuntimeError("collector died")


# ---------------------------------------------------------------------------
# Supervision: worker restart behaviour
# ---------------------------------------------------------------------------


class TestSupervision:
    def test_crash_then_recover_restarts_without_escalating(self, sink):
        # A transient crash is restarted: the pre-crash row AND the recovered
        # session's row are both persisted, and the single crash is reported
        # below the escalation threshold.
        c = _CrashOnceThenStream()
        listener = _RecordingListener()
        w = StreamingWorker(
            c,
            sink,
            "h",
            batch_size=10,
            flush_interval_s=99,
            sleeper=_ImmediateSleep(),
            backoff=_RecordingBackoff(),
            listener=listener,
        )
        w.start()
        time.sleep(0.2)
        w.stop()

        assert c.calls == 2  # crashed session + recovered session
        assert listener.crashes == [1]  # one transient crash, attempt 1
        assert _row_count(sink) == 2

    def test_finite_stream_completes_without_restart(self, sink):
        # A stream that ends on its own is not respawned (no busy-loop).
        c = _PausableStreamCollector([_make_row(), _make_row()], pause_after=0)
        listener = _RecordingListener()
        w = StreamingWorker(
            c,
            sink,
            "h",
            batch_size=1,
            flush_interval_s=99,
            sleeper=_ImmediateSleep(),
            listener=listener,
        )
        w.start()
        time.sleep(0.2)

        assert not w.thread.is_alive()
        assert listener.crashes == []
        assert len(listener.session_ends) == 1  # exactly one session ran
        assert _row_count(sink) == 2

    def test_persistent_flap_escalates_once(self, sink):
        # Every session crashes: the worker backs off and retries, reporting
        # each attempt; the listener halts it once the escalation threshold
        # is reached so the test is deterministic.
        backoff = _RecordingBackoff()
        listener = _RecordingListener(stop_at=3)
        w = StreamingWorker(
            _AlwaysCrash(),
            sink,
            "h",
            batch_size=10,
            flush_interval_s=99,
            sleeper=_ImmediateSleep(),
            backoff=backoff,
            listener=listener,
        )
        listener.stop_event = w.stop_event
        w.start()
        w.thread.join(timeout=2.0)

        assert not w.thread.is_alive()
        assert listener.crashes == [1, 2, 3]  # consecutive, no healthy reset
        assert backoff.attempts == [1, 2, 3]
        assert [a for a in listener.crashes if a >= 3] == [3]  # escalated once

    def test_stop_aborts_pending_backoff(self, sink):
        # A long backoff must not delay shutdown: stop() aborts the wait and
        # the thread joins promptly via the real InterruptibleSleep.
        w = StreamingWorker(
            _AlwaysCrash(),
            sink,
            "h",
            batch_size=10,
            flush_interval_s=99,
            backoff=ExponentialBackoff(30.0, 30.0, 1.0),
            join_timeout_s=2.0,
        )
        w.start()
        time.sleep(0.1)  # let it crash once and enter the 30s backoff wait
        started = time.monotonic()
        w.stop()
        assert not w.thread.is_alive()
        assert time.monotonic() - started < 2.0


# ---------------------------------------------------------------------------
# Supervision: the injected seams in isolation
# ---------------------------------------------------------------------------


class TestSupervisionSeams:
    def test_exponential_backoff_curve(self):
        b = ExponentialBackoff(1.0, 5.0, 2.0)
        assert [b.delay_for(a) for a in (1, 2, 3, 4, 5)] == [1.0, 2.0, 4.0, 5.0, 5.0]

    def test_logging_listener_escalates_at_threshold(self, caplog):
        listener = LoggingSupervisionListener(escalate_threshold=3)
        with caplog.at_level(logging.WARNING, logger="host_monitor"):
            for attempt in (1, 2, 3):
                listener.report_crash("auth_events", attempt, RuntimeError("boom"))
        levels = [r.levelno for r in caplog.records]
        assert levels == [logging.WARNING, logging.WARNING, logging.ERROR]
