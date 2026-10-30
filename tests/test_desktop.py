"""Desktop app wiring: in-process only (no subprocess orchestration), the
dashboard serves on a thread, and the build_runner extract still constructs a
Runner."""

from __future__ import annotations

import logging

import ast
import os
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import avai.desktop as desktop
import pytest


def _imports(src: str) -> set[str]:
    mods: set[str] = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            mods.update(n.name.split(".")[0] for n in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module.split(".")[0])
    return mods


def test_desktop_does_no_subprocess_orchestration() -> None:
    src = Path(desktop.__file__).read_text()
    assert "subprocess" not in _imports(src)  # not imported
    assert "subprocess." not in src  # no subprocess.run / .Popen call
    assert "Popen" not in src


def test_dashboard_opens_control_and_app_mode_without_touching_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from unittest.mock import patch


    monkeypatch.delenv("AVAI_CONTROL_OPEN", raising=False)
    monkeypatch.delenv("AVAI_APP_MODE", raising=False)
    monkeypatch.setattr("avai.desktop.waitress.serve", lambda *a, **k: None)
    with patch("avai.desktop.DashboardApp") as dashboard_app:
        desktop.EmbeddedDashboard(str(tmp_path / "avai.db")).start(0).join(timeout=5)
    config = dashboard_app.call_args.args[0]
    assert config.control_open and config.app_mode
    # .get, not `in os.environ`: a failure must not print the whole env.
    assert os.environ.get("AVAI_CONTROL_OPEN") is None
    assert os.environ.get("AVAI_APP_MODE") is None


WAITRESS_WORKER_PREFIX = "waitress-"
BIND_ATTEMPTS = 50
BIND_WAIT_S = 0.1


class WaitressWorkers:
    """Counts the worker threads waitress starts, one per configured thread."""

    def count(self) -> int:
        names = (thread.name for thread in threading.enumerate())
        return sum(name.startswith(WAITRESS_WORKER_PREFIX) for name in names)

    def wait_for_bind(self, port: int) -> None:
        for _ in range(BIND_ATTEMPTS):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1)
                return
            except (urllib.error.URLError, ConnectionError):
                time.sleep(BIND_WAIT_S)
        raise AssertionError("dashboard thread did not serve")


class TestEmbeddedDashboardThreads:
    def test_app_window_gets_as_many_threads_as_avai_dashboard(
        self, tmp_path: Path
    ) -> None:
        # Regression: the app served with waitress's default 4 threads, so the
        # page's burst of parallel panel requests queued and logged
        # "Task queue depth" warnings (each one a Sentry issue).
        from avai.dashboard.serve import DashboardServer

        workers = WaitressWorkers()
        before = workers.count()
        port = desktop.LoopbackPort().free()
        desktop.EmbeddedDashboard(str(tmp_path / "avai.db")).start(port)
        workers.wait_for_bind(port)
        assert workers.count() - before == DashboardServer.THREADS


def test_dashboard_serves_in_process(tmp_path: Path) -> None:
    db = str(tmp_path / "avai.db")
    port = desktop.LoopbackPort().free()
    desktop.EmbeddedDashboard(db).start(port)
    for _ in range(50):  # wait for waitress to bind
        try:
            resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1)
            assert resp.status == 200
            return
        except (urllib.error.URLError, ConnectionError):
            time.sleep(0.1)
    raise AssertionError("dashboard thread did not serve")


def test_build_runner_constructs_without_network(tmp_path: Path) -> None:
    from avai.host_monitor.main import MonitorArgs, MonitorWiring

    db = str(tmp_path / "m.db")
    flags = ["--db", db, "--no-judge", "--no-enrich", "--no-streaming"]
    args = MonitorArgs().options(flags)
    runner, engine = MonitorWiring(args, logging.getLogger("test")).build()
    try:
        assert runner.config.snapshot_collectors  # collectors wired
        assert runner.config.streaming_collectors == []  # --no-streaming honored
    finally:
        engine.dispose()
