from __future__ import annotations

import json
import subprocess
import threading
from collections.abc import Iterable, Iterator
from typing import Any, Protocol

# How long a terminated child gets to exit before it is killed.
TERMINATE_GRACE_S = 2
DEFAULT_KILLER_NAME = "stream-killer"


class LineParser(Protocol):
    """Converts one decoded JSON event from a tool's stream into a row
    dict matching the collector's model."""

    def parse(self, event: dict[str, Any]) -> dict[str, Any]: ...


class ChildProcess:
    """A streaming child process: stopped on request, reaped on exit."""

    def __init__(self, proc: subprocess.Popen[str]) -> None:
        self._proc = proc

    @classmethod
    def spawn(cls, command: list[str]) -> ChildProcess:
        return cls(
            subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        )

    def watch(self, stop_event: threading.Event, thread_name: str) -> None:
        """Watchdog: when stop_event fires, terminate the subprocess, which
        closes stdout and ends the caller's read loop."""
        threading.Thread(
            target=self.terminate_on, args=(stop_event,), daemon=True, name=thread_name
        ).start()

    def lines(self) -> Iterable[str]:
        return self._proc.stdout or ()

    def terminate_on(self, stop_event: threading.Event) -> None:
        stop_event.wait()
        if self._proc.poll() is None:
            try:
                self._proc.terminate()
            except ProcessLookupError:
                return

    def shut_down(self) -> None:
        if self._proc.poll() is not None:
            return
        try:
            self._proc.terminate()
            self._proc.wait(timeout=TERMINATE_GRACE_S)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        except ProcessLookupError:
            return


class JsonLineStreamSource:
    """Tail a subprocess that emits one JSON object per stdout line.

    The read loop terminates when ``stop_event`` is set (a watchdog
    thread terminates the child, closing stdout) or when the child exits
    on its own. Blank lines and undecodable lines are skipped.
    """

    def __init__(
        self,
        command: list[str],
        parser: LineParser,
        killer_name: str = DEFAULT_KILLER_NAME,
    ) -> None:
        self._command = command
        self._parser = parser
        self._killer_name = killer_name

    def stream(self, stop_event: threading.Event) -> Iterator[dict[str, Any]]:
        child = ChildProcess.spawn(self._command)
        child.watch(stop_event, self._killer_name)
        try:
            for event in self._json_events(child.lines(), stop_event):
                yield self._parser.parse(event)
        finally:
            child.shut_down()

    def _json_events(
        self, lines: Iterable[str], stop_event: threading.Event
    ) -> Iterator[dict[str, Any]]:
        """Each line decoded as JSON, until ``stop_event`` is set. Lines that
        aren't JSON (blank ones included) are skipped."""
        for line in lines:
            if stop_event.is_set():
                return
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
