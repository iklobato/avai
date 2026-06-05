"""Background worker that drives one StreamingCollector in a thread."""
from __future__ import annotations

import threading
import time
from typing import Optional

from .constants import LOG
from .runtime import Clock, Digest
from .sink import Sink
from .collectors import StreamingCollector


class StreamingWorker:
    """Long-lived execution policy for a :class:`StreamingCollector`.

    Owns one OS thread, one ``StreamingSession`` row (its ``run_id``),
    and a small write buffer. Buffered rows are flushed when the buffer
    reaches ``batch_size`` *or* ``flush_interval_s`` has elapsed since
    the last flush, whichever comes first. ``stop()`` signals the
    collector to terminate its source and joins the thread.
    """

    def __init__(
        self,
        collector: StreamingCollector,
        sink: Sink,
        hostname: str,
        batch_size: int = 50,
        flush_interval_s: float = 5.0,
        join_timeout_s: float = 5.0,
    ):
        self.collector = collector
        self.sink = sink
        self.hostname = hostname
        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s
        self.join_timeout_s = join_timeout_s
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.run_id: Optional[str] = None
        self._rows_written = 0

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
        self.run_id = self.sink.start_streaming_session(
            self.collector.name,
            self.hostname,
        )
        LOG.info(
            "streaming collector=%s run_id=%s started", self.collector.name, self.run_id
        )
        buffer: list[dict] = []
        last_flush = time.monotonic()
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
        except Exception:
            LOG.exception("streaming collector=%s crashed", self.collector.name)
        finally:
            try:
                self._flush(buffer)
            except Exception:
                LOG.exception(
                    "streaming final flush failed collector=%s", self.collector.name
                )
            try:
                self.sink.end_streaming_session(self.run_id, self._rows_written)
            except Exception:
                LOG.exception(
                    "end_streaming_session failed collector=%s", self.collector.name
                )
            LOG.info(
                "streaming collector=%s run_id=%s stopped rows=%d",
                self.collector.name,
                self.run_id,
                self._rows_written,
            )
