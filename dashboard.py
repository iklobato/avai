#!/usr/bin/env python3
"""dashboard.py — single-page web dashboard for avai/host_monitor.

Reads the SQLite database written by ``host_monitor.py`` via the same
SQLAlchemy ORM models, then renders a Jinja2 template (Flask) showing:

  - latest run metadata and per-collector row counts
  - system-integrity snapshot
  - verdict counts across all judgments
  - non-benign findings (malicious / suspicious / unknown), each joined
    back to its underlying collector row so the affected artifact is
    visible
  - the most recent runs
  - collector errors from the latest run

The page auto-refreshes every 30 seconds.

Usage
-----
    python3 dashboard.py                       # localhost:8765
    python3 dashboard.py --port 9000
    python3 dashboard.py --db /path/to/db
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from flask import Flask, current_app, render_template
from sqlalchemy import create_engine, desc, func, select
from sqlalchemy.orm import Session

# Reuse the models from host_monitor.py — no raw SQL, single source of truth.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_monitor import (  # noqa: E402
    BrowserExtensionRow,
    BluetoothDeviceRow,
    CollectionRun,
    CollectorErrorRow,
    FileIntegrityRow,
    InstalledAppRow,
    Judgement,
    LaunchItemRow,
    ListeningPortRow,
    NetworkConnectionRow,
    NetworkInterfaceRow,
    ProcessRow,
    QuarantineEventRow,
    SystemIntegrityRow,
    TccPermissionRow,
    UsbDeviceRow,
    WifiStateRow,
    AuthEventRow,
)


COLLECTOR_MODELS = {
    "processes":           ProcessRow,
    "network_connections": NetworkConnectionRow,
    "listening_ports":     ListeningPortRow,
    "network_interfaces":  NetworkInterfaceRow,
    "usb_devices":         UsbDeviceRow,
    "bluetooth_devices":   BluetoothDeviceRow,
    "wifi_state":          WifiStateRow,
    "launch_items":        LaunchItemRow,
    "tcc_permissions":     TccPermissionRow,
    "quarantine_events":   QuarantineEventRow,
    "browser_extensions":  BrowserExtensionRow,
    "system_integrity":    SystemIntegrityRow,
    "auth_events":         AuthEventRow,
    "file_integrity":      FileIntegrityRow,
    "installed_apps":      InstalledAppRow,
}

# Which fields identify an artifact for display in the findings table.
DISPLAY_FIELDS: dict[str, tuple[str, ...]] = {
    "processes":           ("name", "exe"),
    "listening_ports":     ("process_name", "laddr_port"),
    "usb_devices":         ("name", "manufacturer"),
    "bluetooth_devices":   ("name",),
    "wifi_state":          ("ssid",),
    "launch_items":        ("label", "path"),
    "tcc_permissions":     ("client", "service"),
    "quarantine_events":   ("agent_name", "origin_url"),
    "browser_extensions":  ("name", "browser"),
    "system_integrity":    (),
    "file_integrity":      ("path",),
    "installed_apps":      ("name", "bundle_id"),
}

SEVERITY_ORDER = {
    "malicious":  0,
    "suspicious": 1,
    "unknown":    2,
    "benign":     3,
}

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "host_monitor.db"

app = Flask(__name__)
app.config["DB_PATH"] = str(DEFAULT_DB_PATH)


def _engine():
    return create_engine(f"sqlite:///{current_app.config['DB_PATH']}")


def _artifact_for(session: Session, judgment: Judgement) -> str:
    """Join a judgment back to its collector row and produce a display string."""
    model = COLLECTOR_MODELS.get(judgment.collector)
    fields = DISPLAY_FIELDS.get(judgment.collector, ())
    if model is None or not fields:
        return ""
    row = session.execute(
        select(model)
        .where(model.content_hash == judgment.content_hash)
        .limit(1)
    ).scalar_one_or_none()
    if row is None:
        return ""
    parts = [str(getattr(row, f)) for f in fields if getattr(row, f) is not None]
    return " · ".join(parts)


def _collect_row_counts(session: Session, run_id: str) -> list[dict]:
    out = []
    for name, model in COLLECTOR_MODELS.items():
        n = session.execute(
            select(func.count()).select_from(model).where(model.run_id == run_id)
        ).scalar() or 0
        out.append({"name": name, "rows": n})
    out.sort(key=lambda x: x["rows"], reverse=True)
    return out


@app.route("/")
def dashboard():
    with Session(_engine()) as session:
        latest = session.execute(
            select(CollectionRun)
            .order_by(desc(CollectionRun.started_at))
            .limit(1)
        ).scalar_one_or_none()

        recent_runs = session.execute(
            select(CollectionRun)
            .order_by(desc(CollectionRun.started_at))
            .limit(10)
        ).scalars().all()

        runs_total = session.execute(
            select(func.count()).select_from(CollectionRun)
        ).scalar() or 0

        verdict_counts = dict(session.execute(
            select(Judgement.verdict, func.count(Judgement.content_hash))
            .group_by(Judgement.verdict)
        ).all())

        # Newest-judged non-benign findings (cap to keep the page snappy).
        findings_raw = session.execute(
            select(Judgement)
            .where(Judgement.verdict != "benign")
            .order_by(desc(Judgement.created_at))
            .limit(200)
        ).scalars().all()

        findings = []
        for j in findings_raw:
            findings.append({
                "verdict":     j.verdict,
                "collector":   j.collector,
                "category":    j.category or "none",
                "confidence":  j.confidence or 0.0,
                "reasoning":   j.reasoning or "",
                "created_at":  j.created_at,
                "artifact":    _artifact_for(session, j),
            })
        findings.sort(key=lambda f: (
            SEVERITY_ORDER.get(f["verdict"], 99),
            -f["confidence"],
        ))

        row_counts: list[dict] = []
        errors: list[CollectorErrorRow] = []
        sysint: SystemIntegrityRow | None = None
        judged_this_run = 0
        if latest is not None:
            row_counts = _collect_row_counts(session, latest.run_id)
            errors = session.execute(
                select(CollectorErrorRow)
                .where(CollectorErrorRow.run_id == latest.run_id)
            ).scalars().all()
            sysint = session.execute(
                select(SystemIntegrityRow)
                .where(SystemIntegrityRow.run_id == latest.run_id)
                .limit(1)
            ).scalar_one_or_none()
            judged_this_run = session.execute(
                select(func.count(Judgement.content_hash))
                .where(Judgement.created_at >= latest.started_at)
            ).scalar() or 0

    return render_template(
        "dashboard.html",
        latest_run=latest,
        recent_runs=recent_runs,
        runs_total=runs_total,
        verdict_counts=verdict_counts,
        findings=findings,
        row_counts=row_counts,
        errors=errors,
        sysint=sysint,
        judged_this_run=judged_this_run,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="avai host monitor — single-page dashboard"
    )
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH),
                        help=f"SQLite database path (default: {DEFAULT_DB_PATH})")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    app.config["DB_PATH"] = args.db
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


if __name__ == "__main__":
    sys.exit(main())
