"""Desktop app wiring: in-process only (no subprocess orchestration), the
dashboard serves on a thread, and the build_runner extract still constructs a
Runner."""

from __future__ import annotations

import ast
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
        assert runner.snapshot_collectors  # collectors wired
        assert runner.streaming_collectors == []  # --no-streaming honored
    finally:
        engine.dispose()
