"""Supervision policy for long-lived streaming workers.

Splits *what to do when a StreamingCollector dies* out of the worker
itself. The :class:`~.streaming.StreamingWorker` owns a thread and a write
buffer; these collaborators own the three decisions a crash forces:

* :class:`BackoffPolicy` — how long to wait before the next restart.
* :class:`Sleeper` — how to wait (interruptibly, so shutdown is prompt).
* :class:`SupervisionListener` — whether a crash is still transient (log
  and retry) or a persistent fault that escalates to ERROR — the signal an
  external logging->monitoring handler forwards.

Each is a Protocol the worker depends on, wired with a production default
in the worker's constructor and swappable for a deterministic fake in
tests. The outcome of one streaming session is modelled as an explicit
:class:`StreamOutcome` the supervisor dispatches on polymorphically, so the
restart loop never branches on a status field.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .constants import (
    LOG,
    STREAM_CRASH_ESCALATE_THRESHOLD,
    STREAM_RESTART_BACKOFF_FACTOR,
    STREAM_RESTART_BASE_BACKOFF_S,
    STREAM_RESTART_MAX_BACKOFF_S,
)

# --- Outcome of one streaming session --------------------------------------


class OutcomeHandler(Protocol):
    """The supervisor side of the double dispatch. Each handler performs
    the side effect for its outcome and returns whether the supervision
    loop should run another session."""

    def on_completed(self) -> bool: ...

    def on_stopped(self) -> bool: ...

    def on_crashed(self, exc: BaseException) -> bool: ...


class StreamOutcome(Protocol):
    """Result of one streaming session. Tells the supervisor what happened
    without the supervisor inspecting a 'kind' field."""

    def accept(self, handler: OutcomeHandler) -> bool: ...


class Completed:
    """The collector's stream ended on its own (a finite source ran dry)."""

    def accept(self, handler: OutcomeHandler) -> bool:
        return handler.on_completed()


class Stopped:
    """The stream ended because shutdown was requested."""

    def accept(self, handler: OutcomeHandler) -> bool:
        return handler.on_stopped()


class Crashed:
    """The collector raised mid-stream."""

    def __init__(self, exc: BaseException) -> None:
        self.exc = exc

    def accept(self, handler: OutcomeHandler) -> bool:
        return handler.on_crashed(self.exc)


# --- Restart timing --------------------------------------------------------


@runtime_checkable
class BackoffPolicy(Protocol):
    def delay_for(self, attempt: int) -> float:
        """Seconds to wait before restart ``attempt`` (1-based)."""
        ...


class ExponentialBackoff:
    """Binary exponential backoff capped at a ceiling.

    ``attempt`` is 1-based: the first restart waits ``base_s``, then each
    subsequent one multiplies by ``factor`` until ``max_s`` is reached.
    """

    def __init__(self, base_s: float, max_s: float, factor: float) -> None:
        self._base = base_s
        self._max = max_s
        self._factor = factor

    def delay_for(self, attempt: int) -> float:
        raw = self._base * (self._factor ** max(0, attempt - 1))
        return min(raw, self._max)


@runtime_checkable
class Sleeper(Protocol):
    def sleep(self, seconds: float) -> None: ...


class InterruptibleSleep:
    """Waits on a stop ``Event`` so a pending backoff aborts the moment
    shutdown is requested instead of blocking for the full delay."""

    def __init__(self, stop_event) -> None:
        self._stop = stop_event

    def sleep(self, seconds: float) -> None:
        self._stop.wait(timeout=seconds)


# --- Crash escalation ------------------------------------------------------


class SupervisionListener(Protocol):
    def report_crash(
        self, collector: str, attempt: int, exc: BaseException
    ) -> None: ...

    def report_healthy(self, collector: str) -> None: ...

    def report_session_end(self, collector: str, rows: int) -> None: ...


class LoggingSupervisionListener:
    """Default listener. Logs transient restarts at WARNING and escalates
    to ERROR once a collector has crashed ``escalate_threshold`` times in a
    row with no healthy run between.

    The ERROR is the line an external logging->monitoring handler forwards.
    Gating it behind a healthy-run reset means a one-off or intentional
    crash logs a WARNING and recovers silently; only a genuinely flapping
    collector pages.
    """

    def __init__(
        self, escalate_threshold: int = STREAM_CRASH_ESCALATE_THRESHOLD
    ) -> None:
        self._threshold = escalate_threshold

    def report_crash(self, collector: str, attempt: int, exc: BaseException) -> None:
        if attempt >= self._threshold:
            LOG.error(
                "streaming collector=%s crashed %d× consecutively; last error: %r",
                collector,
                attempt,
                exc,
            )
            return
        LOG.warning(
            "streaming collector=%s crashed (attempt %d), restarting: %r",
            collector,
            attempt,
            exc,
        )

    def report_healthy(self, collector: str) -> None:
        LOG.info("streaming collector=%s recovered after restart", collector)

    def report_session_end(self, collector: str, rows: int) -> None:
        LOG.info("streaming collector=%s session ended rows=%d", collector, rows)


def default_backoff() -> ExponentialBackoff:
    """Production backoff wired from the tuned constants."""
    return ExponentialBackoff(
        STREAM_RESTART_BASE_BACKOFF_S,
        STREAM_RESTART_MAX_BACKOFF_S,
        STREAM_RESTART_BACKOFF_FACTOR,
    )
