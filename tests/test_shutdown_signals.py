"""ShutdownSignals: the first SIGINT/SIGTERM is a normal, asked-for stop."""

from __future__ import annotations

import logging
import signal

import pytest

from avai.host_monitor.main import ShutdownSignals


class _StoppableRunner:
    def __init__(self) -> None:
        self.shutdowns = 0

    def request_shutdown(self) -> None:
        self.shutdowns += 1


class TestShutdownSignals:
    STOPPING = (
        f"received signal {signal.SIGTERM.value}; stopping after the"
        " current step (press Ctrl-C again to force-quit now)"
    )

    def test_first_sigterm_stops_gracefully_without_a_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # launchd, systemd and the desktop app stop the monitor with SIGTERM:
        # an expected stop, so not a warning (it was Sentry AVAI-CLI-D).
        caplog.set_level(logging.DEBUG, logger="test")
        runner = _StoppableRunner()

        ShutdownSignals(runner, logging.getLogger("test")).on_signal(
            signal.SIGTERM, None
        )

        logged = [(record.levelno, record.getMessage()) for record in caplog.records]
        assert runner.shutdowns == 1
        assert logged == [(logging.INFO, self.STOPPING)]
