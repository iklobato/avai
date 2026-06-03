"""Long-lived line-stream source for streaming collectors.

Every streaming collector tails a native tool (``log stream``,
``journalctl -f``, ``eslogger``) the same way: spawn the process, run a
watchdog thread that terminates it when the stop event fires, and read
stdout line by line, decoding each line as a JSON object and converting
it to a row.

That loop — the part with the subprocess and signal-handling bugs — is
invariant. Only two things vary: the **command** and the **row parser**.
:class:`JsonLineStreamSource` owns the invariant loop; the command is
passed in and the parser is a :class:`LineParser` strategy injected per
OS. The parsers are pure ``dict -> dict`` transforms, so they're unit
tested without spawning anything.
"""

from __future__ import annotations

import json
import subprocess
import threading
from typing import Iterable, Protocol


class LineParser(Protocol):
    """Converts one decoded JSON event from a tool's stream into a row
    dict matching the collector's model."""

    def parse(self, event: dict) -> dict: ...


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
        *,
        killer_name: str = "stream-killer",
    ) -> None:
        self._command = command
        self._parser = parser
        self._killer_name = killer_name

    def stream(self, stop_event: threading.Event) -> Iterable[dict]:
        proc = subprocess.Popen(
            self._command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )

        # Watchdog: when stop_event fires, terminate the subprocess,
        # which closes stdout and ends the read loop below.
        def _terminator() -> None:
            stop_event.wait()
            if proc.poll() is None:
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass

        threading.Thread(
            target=_terminator, daemon=True, name=self._killer_name
        ).start()

        try:
            for line in proc.stdout:
                if stop_event.is_set():
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                yield self._parser.parse(event)
        finally:
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                except ProcessLookupError:
                    pass
