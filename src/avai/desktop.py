"""In-process desktop app: the dashboard and the monitor run as threads in one
process behind a native window. No subprocess orchestration (the collectors
still read OS tools like journalctl/tcpdump, but that is the data source, not
app wiring). Shares the same ~/.avai/avai.db as the `avai monitor`/`dashboard`
CLIs, so there is no split-brain DB.

The GUI dep (pywebview) is an optional extra; `avai app` tells you how to
install it if missing. The dashboard + monitor run headless without it.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

import waitress
from flask import Flask

from avai.dashboard import DashboardApp, DashboardConfig, DashboardSchema
from avai.dashboard.serve import DashboardServer
from avai.host_monitor.constants import DEFAULT_DB_PATH, LOGGER_NAME
from avai.host_monitor.main import MonitorArgs, MonitorWiring
from avai.host_monitor.runner import Runner

LOOPBACK_HOST = "127.0.0.1"
ANY_FREE_PORT = 0
GUI_MISSING = "avai app needs the GUI extra: pip install 'avai-monitor[app]'"


class LoopbackPort:
    def free(self) -> int:
        # ponytail: bind-then-reuse has a tiny TOCTOU race, fine for a
        # single-user localhost app. Use a fixed port + a settings screen if
        # that ever matters.
        with socket.socket() as probe:
            probe.bind((LOOPBACK_HOST, ANY_FREE_PORT))
            return probe.getsockname()[1]


class DesktopSettings:
    """The JSON file the settings screen writes next to the DB."""

    FILE_NAME = "config.json"

    def __init__(self, path: Path) -> None:
        self._path = path

    @classmethod
    def default(cls) -> DesktopSettings:
        return cls(Path(DEFAULT_DB_PATH).expanduser().parent / cls.FILE_NAME)

    def api_key(self) -> str | None:
        """The LLM key the settings screen wrote, or None (viz-only)."""
        try:
            return json.loads(self._path.read_text()).get("api_key") or None
        except (OSError, ValueError):
            return None


class EmbeddedDashboard:
    """Serves the existing Flask dashboard on a daemon thread. Read-only, so
    no explicit stop is needed: it dies with the process."""

    def __init__(self, db: str) -> None:
        self._db = db

    def start(self, port: int) -> threading.Thread:
        thread = threading.Thread(
            target=waitress.serve,
            args=(self._app(),),
            # Same thread count as `avai dashboard`: the page fires many panel
            # requests at once, and waitress's default 4 queues them.
            kwargs={
                "host": LOOPBACK_HOST,
                "port": port,
                "threads": DashboardServer.THREADS,
            },
            daemon=True,
            name="avai-dashboard",
        )
        thread.start()
        return thread

    def _app(self) -> Flask:
        # The window is a single-user loopback webview the user owns, so
        # control needs no token (the token is only a CSRF defence for a
        # network dashboard). App mode -> antivirus-style protection home at
        # the top of the dashboard. Defaults only: a value the user exported
        # still wins.
        environ = {"AVAI_CONTROL_OPEN": "1", "AVAI_APP_MODE": "1", **os.environ}
        DashboardSchema().ensure(self._db)
        return DashboardApp(DashboardConfig.from_env(self._db, environ)).build()


class EmbeddedMonitor:
    """Builds the monitor in-process and runs its loop on a daemon thread.
    ``start`` returns the Runner so the caller can ``request_shutdown()`` on
    window close (which also terminates the monitor's journalctl -f /
    eslogger children)."""

    def __init__(self, db: str) -> None:
        self._db = db

    def start(self, api_key: str | None) -> Runner:
        if api_key:
            os.environ.setdefault("ANTHROPIC_API_KEY", api_key)
        # No key yet -> viz-only (NullJudge); the settings screen enables the
        # judge.
        argv = ["--db", self._db] if api_key else ["--db", self._db, "--no-judge"]
        args = MonitorArgs().options(argv)
        runner, engine = MonitorWiring(args, logging.getLogger(LOGGER_NAME)).build()
        loop = MonitorLoop(runner, engine.dispose)
        threading.Thread(
            target=loop.serve_until_shutdown,
            args=(args.interval,),
            daemon=True,
            name="avai-monitor",
        ).start()
        return runner


class MonitorLoop:
    def __init__(self, runner: Runner, release: Callable[[], None]) -> None:
        self._runner = runner
        self._release = release

    def serve_until_shutdown(self, interval: int) -> None:
        self._runner.start_streaming()
        try:
            self._runner.run_forever(interval)
        finally:
            self._runner.stop_streaming()
            self._release()


class DesktopApp:
    """The dashboard and the monitor behind one native window."""

    WINDOW_TITLE = "avai"
    WINDOW_WIDTH = 1280
    WINDOW_HEIGHT = 860

    def __init__(self, db: str, err: TextIO) -> None:
        self._db = db
        self._err = err

    @classmethod
    def main(cls) -> int:
        return cls(str(Path(DEFAULT_DB_PATH).expanduser()), sys.stderr).launch()

    def launch(self) -> int:
        try:
            import webview
        except ImportError:
            self._err.write(GUI_MISSING + "\n")
            return 1
        port = LoopbackPort().free()
        EmbeddedDashboard(self._db).start(port)
        runner = EmbeddedMonitor(self._db).start(DesktopSettings.default().api_key())
        webview.create_window(
            self.WINDOW_TITLE,
            f"http://{LOOPBACK_HOST}:{port}",
            width=self.WINDOW_WIDTH,
            height=self.WINDOW_HEIGHT,
        )
        webview.start()  # blocks on the main thread until the window is closed
        runner.request_shutdown()
        return 0
