"""Desktop app wiring: in-process only (no subprocess orchestration), the
dashboard serves on a thread, and the build_runner extract still constructs a
Runner."""

from __future__ import annotations

import ast
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

import avai.desktop as desktop


def _imports(src: str) -> set[str]:
    mods: set[str] = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            mods.update(n.name.split(".")[0] for n in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module.split(".")[0])
    return mods


def test_desktop_does_no_subprocess_orchestration():
    src = Path(desktop.__file__).read_text()
    assert "subprocess" not in _imports(src)  # not imported
    assert "subprocess." not in src  # no subprocess.run / .Popen call
    assert "Popen" not in src


def test_dashboard_opens_control_and_app_mode_without_touching_env(
    tmp_path, monkeypatch
):
    from unittest.mock import patch

    import waitress

    monkeypatch.delenv("AVAI_CONTROL_OPEN", raising=False)
    monkeypatch.delenv("AVAI_APP_MODE", raising=False)
    monkeypatch.setattr(waitress, "serve", lambda *a, **k: None)
    with patch("avai.dashboard.create_app") as create_app:
        desktop._start_dashboard(str(tmp_path / "avai.db"), 0).join(timeout=5)
    config = create_app.call_args.args[0]
    assert config.control_open and config.app_mode
    # .get, not `in os.environ`: a failure must not print the whole env.
    assert os.environ.get("AVAI_CONTROL_OPEN") is None
    assert os.environ.get("AVAI_APP_MODE") is None


def test_dashboard_serves_in_process(tmp_path):
    db = str(tmp_path / "avai.db")
    port = desktop._free_port()
    desktop._start_dashboard(db, port)
    for _ in range(50):  # wait for waitress to bind
        try:
            resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1)
            assert resp.status == 200
            return
        except (urllib.error.URLError, ConnectionError):
            time.sleep(0.1)
    raise AssertionError("dashboard thread did not serve")


def test_build_runner_constructs_without_network(tmp_path):
    from avai.host_monitor.main import _build_parser, build_runner

    args = _build_parser().parse_args(
        ["--db", str(tmp_path / "m.db"), "--no-judge", "--no-enrich", "--no-streaming"]
    )
    runner, engine = build_runner(args)
    try:
        assert runner.config.snapshot_collectors  # collectors wired
        assert runner.config.streaming_collectors == []  # --no-streaming honored
    finally:
        engine.dispose()
