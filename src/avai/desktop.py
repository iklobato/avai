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
import os
import socket
import sys
import threading
from pathlib import Path

from avai.host_monitor.constants import DEFAULT_DB_PATH

CONFIG_PATH = Path(DEFAULT_DB_PATH).expanduser().parent / "config.json"


def _free_port() -> int:
    # ponytail: bind-then-reuse has a tiny TOCTOU race, fine for a single-user
    # localhost app. Use a fixed port + a settings screen if that ever matters.
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _load_api_key(path: Path = CONFIG_PATH) -> str | None:
    """Read the LLM key the settings screen wrote, or None (viz-only)."""
    try:
        return json.loads(path.read_text()).get("api_key") or None
    except (OSError, ValueError):
        return None


def _start_dashboard(db: str, port: int) -> threading.Thread:
    """Serve the existing Flask dashboard on a daemon thread. Read-only, so no
    explicit stop is needed: it dies with the process."""
    import waitress

    from avai.dashboard import _ensure_db_exists, app

    _ensure_db_exists(db)
    app.config["DB_PATH"] = db
    thread = threading.Thread(
        target=lambda: waitress.serve(app, host="127.0.0.1", port=port),
        daemon=True,
        name="avai-dashboard",
    )
    thread.start()
    return thread


def _start_monitor(db: str, api_key: str | None):
    """Build the monitor in-process and run its loop on a daemon thread.
    Returns the Runner so the caller can ``request_shutdown()`` on window close
    (which also terminates the monitor's journalctl -f / eslogger children)."""
    from avai.host_monitor.main import _build_parser, build_runner

    if api_key:
        os.environ.setdefault("ANTHROPIC_API_KEY", api_key)
    # No key yet -> viz-only (NullJudge); the settings screen enables the judge.
    argv = ["--db", db] if api_key else ["--db", db, "--no-judge"]
    args = _build_parser().parse_args(argv)
    runner, engine = build_runner(args)

    def _run() -> None:
        runner.start_streaming()
        try:
            runner.run_forever(args.interval)
        finally:
            runner.stop_streaming()
            engine.dispose()

    threading.Thread(target=_run, daemon=True, name="avai-monitor").start()
    return runner


def main() -> int:
    try:
        import webview
    except ImportError:
        print(
            "avai app needs the GUI extra: pip install 'avai-monitor[app]'",
            file=sys.stderr,
        )
        return 1

    db = str(Path(DEFAULT_DB_PATH).expanduser())
    port = _free_port()
    _start_dashboard(db, port)
    runner = _start_monitor(db, _load_api_key())

    webview.create_window("avai", f"http://127.0.0.1:{port}", width=1280, height=860)
    webview.start()  # blocks on the main thread until the window is closed
    runner.request_shutdown()
    return 0
