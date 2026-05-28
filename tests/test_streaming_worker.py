"""Tests for ``StreamingWorker`` — long-lived background thread that
flushes rows to a Sink in batches.

These exercise the worker's lifecycle and buffering behaviour with
a synthetic streaming collector — no journalctl / eslogger needed.
"""
from __future__ import annotations

import threading
import time

import pytest
from sqlalchemy import create_engine

from avai.host_monitor import (
    AuthEventRow,
    Sink,
    StreamingWorker,
)


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
    engine = create_engine(f"sqlite:///{db}",
                           connect_args={"check_same_thread": False})
    s = Sink(engine)
    s.setup()
    return s


def _make_row(action="login_ok", user="alice"):
    return {"timestamp": "2026-05-28T00:00:00+00:00",
            "facility": "auth", "host": "h", "process": "sshd",
            "pid": 1, "message": "x", "action": action, "user": user}


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
        w = StreamingWorker(c, sink, "h",
                            batch_size=5, flush_interval_s=99)
        w.start()
        # Wait for the worker to consume + flush.
        time.sleep(0.2)
        w.stop()

        from sqlalchemy import select, func
        from sqlalchemy.orm import Session
        with Session(sink.engine) as s:
            n = s.execute(select(func.count()).select_from(AuthEventRow)).scalar()
        assert n == 5
        assert w._rows_written == 5

    def test_flushes_on_interval_below_batch_size(self, sink):
        rows = [_make_row(user=f"u{i}") for i in range(2)]
        c = _PausableStreamCollector(rows, pause_after=2)
        # Big batch, fast interval → should flush by interval.
        w = StreamingWorker(c, sink, "h",
                            batch_size=999, flush_interval_s=0.1)
        w.start()
        time.sleep(0.4)
        w.stop()
        # Both rows ended up flushed (either via interval or final flush).
        from sqlalchemy import select, func
        from sqlalchemy.orm import Session
        with Session(sink.engine) as s:
            n = s.execute(select(func.count()).select_from(AuthEventRow)).scalar()
        assert n == 2

    def test_final_flush_on_shutdown_drains_buffer(self, sink):
        # 3 rows, batch size 10 → buffer has 3 at stop time. The final
        # flush in the worker's `finally` should write them.
        rows = [_make_row(user=f"u{i}") for i in range(3)]
        c = _PausableStreamCollector(rows, pause_after=3)
        w = StreamingWorker(c, sink, "h",
                            batch_size=100, flush_interval_s=99)
        w.start()
        time.sleep(0.2)
        w.stop()
        from sqlalchemy import select, func
        from sqlalchemy.orm import Session
        with Session(sink.engine) as s:
            n = s.execute(select(func.count()).select_from(AuthEventRow)).scalar()
        assert n == 3


# ---------------------------------------------------------------------------
# Resilience to bad rows / collector exceptions
# ---------------------------------------------------------------------------

class TestResilience:
    def test_collector_crash_is_caught(self, sink):
        class _Crashing:
            name = "auth_events"
            model = AuthEventRow
            judge_enabled = False
            judge_fields = ()
            judge_hints = ""
            def stream(self, stop_event):
                yield _make_row()
                raise RuntimeError("collector died")

        c = _Crashing()
        w = StreamingWorker(c, sink, "h",
                            batch_size=10, flush_interval_s=99)
        w.start()
        time.sleep(0.2)
        # Thread terminated cleanly despite the exception.
        assert not w.thread.is_alive()
        # The one row before the crash should still be persisted via
        # the final flush in `finally`.
        from sqlalchemy import select, func
        from sqlalchemy.orm import Session
        with Session(sink.engine) as s:
            n = s.execute(select(func.count()).select_from(AuthEventRow)).scalar()
        assert n == 1
