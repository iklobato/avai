#!/usr/bin/env python3
"""dashboard.py — single-page web dashboard for avai/host_monitor.

Architecture
------------
Three layers:

  Service  — pure DB query functions over the host_monitor SQLAlchemy
             models. No Flask, no templates. Each function returns a
             plain Python value (model row, list of dicts, or scalar).

  Routes   — thin Flask handlers. Each route opens a Session, calls one
             or more service functions, and renders either the full
             page shell or one HTML fragment (HTMX swap target). A
             single JSON endpoint feeds the Chart.js verdict series.

  Templates — full shell + per-section partials. HTMX-driven polling
             keeps each partial fresh without full-page reloads;
             changing the verdict filter is also an HTMX swap.

UI stack: Tailwind via Play CDN + HTMX 2 + Chart.js 4. No build step,
no npm.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, current_app, jsonify, render_template, request
from sqlalchemy import create_engine, desc, func, select
from sqlalchemy.orm import Session

# Reuse models from host_monitor.py — single source of schema truth.
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
    StreamingSession,
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

SEVERITY_ORDER = {"malicious": 0, "suspicious": 1, "unknown": 2, "benign": 3}
VERDICTS = ("malicious", "suspicious", "unknown", "benign")

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "host_monitor.db"

app = Flask(__name__)
app.config["DB_PATH"] = str(DEFAULT_DB_PATH)


def _engine():
    return create_engine(f"sqlite:///{current_app.config['DB_PATH']}")


def _session() -> Session:
    return Session(_engine())


# ============================================================================
# Service layer — pure DB queries, no Flask
# ============================================================================

def latest_run(session: Session):
    return session.execute(
        select(CollectionRun)
        .order_by(desc(CollectionRun.started_at))
        .limit(1)
    ).scalar_one_or_none()


def recent_runs(session: Session, limit: int = 10) -> list[CollectionRun]:
    return list(session.execute(
        select(CollectionRun)
        .order_by(desc(CollectionRun.started_at))
        .limit(limit)
    ).scalars())


def runs_total(session: Session) -> int:
    return session.execute(
        select(func.count()).select_from(CollectionRun)
    ).scalar() or 0


def verdict_counts(session: Session) -> dict[str, int]:
    return dict(session.execute(
        select(Judgement.verdict, func.count(Judgement.content_hash))
        .group_by(Judgement.verdict)
    ).all())


def judged_since(session: Session, since: str) -> int:
    return session.execute(
        select(func.count(Judgement.content_hash))
        .where(Judgement.created_at >= since)
    ).scalar() or 0


def _artifact_for(session: Session, j: Judgement) -> str:
    model = COLLECTOR_MODELS.get(j.collector)
    fields = DISPLAY_FIELDS.get(j.collector, ())
    if model is None or not fields:
        return ""
    row = session.execute(
        select(model)
        .where(model.content_hash == j.content_hash)
        .limit(1)
    ).scalar_one_or_none()
    if row is None:
        return ""
    parts = [str(getattr(row, f)) for f in fields if getattr(row, f) is not None]
    return " · ".join(parts)


def findings(session: Session, verdict_filter: str | None = None,
             limit: int = 200) -> list[dict]:
    stmt = select(Judgement)
    if verdict_filter and verdict_filter in VERDICTS:
        stmt = stmt.where(Judgement.verdict == verdict_filter)
    else:
        stmt = stmt.where(Judgement.verdict != "benign")
    stmt = stmt.order_by(desc(Judgement.created_at)).limit(limit)
    raw = session.execute(stmt).scalars().all()
    out = []
    for j in raw:
        out.append({
            "verdict":     j.verdict,
            "collector":   j.collector,
            "category":    j.category or "none",
            "confidence":  j.confidence or 0.0,
            "reasoning":   j.reasoning or "",
            "remediation": j.remediation or "",
            "created_at":  j.created_at,
            "artifact":    _artifact_for(session, j),
        })
    out.sort(key=lambda f: (
        SEVERITY_ORDER.get(f["verdict"], 99),
        -f["confidence"],
    ))
    return out


def row_counts(session: Session, since: str) -> list[dict]:
    out = []
    for name, model in COLLECTOR_MODELS.items():
        n = session.execute(
            select(func.count())
            .select_from(model)
            .where(model.collected_at >= since)
        ).scalar() or 0
        out.append({"name": name, "rows": n})
    out.sort(key=lambda x: x["rows"], reverse=True)
    return out


def collector_errors(session: Session, run_id: str) -> list[CollectorErrorRow]:
    return list(session.execute(
        select(CollectorErrorRow)
        .where(CollectorErrorRow.run_id == run_id)
    ).scalars())


def system_integrity(session: Session, run_id: str):
    return session.execute(
        select(SystemIntegrityRow)
        .where(SystemIntegrityRow.run_id == run_id)
        .limit(1)
    ).scalar_one_or_none()


def verdict_timeseries(session: Session, hours: int = 12) -> dict:
    """Return verdict counts grouped per-hour bucket over the last N hours.
    Returns: {"labels": [...iso hours...], "datasets": {verdict: [counts...]}}
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)
              ).isoformat(timespec="seconds")
    # 'YYYY-MM-DDTHH' is the first 13 chars of an ISO timestamp.
    rows = session.execute(
        select(
            func.substr(Judgement.created_at, 1, 13).label("hour"),
            Judgement.verdict,
            func.count().label("n"),
        )
        .where(Judgement.created_at >= cutoff)
        .group_by("hour", Judgement.verdict)
        .order_by("hour")
    ).all()
    buckets: dict[str, dict[str, int]] = {}
    for hour, verdict, n in rows:
        buckets.setdefault(hour, {})
        buckets[hour][verdict] = buckets[hour].get(verdict, 0) + n
    labels = sorted(buckets.keys())
    datasets = {v: [buckets[h].get(v, 0) for h in labels] for v in VERDICTS}
    return {"labels": labels, "datasets": datasets}


# ============================================================================
# Routes — full page + HTMX fragments + chart JSON
# ============================================================================

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/fragments/header-meta")
def fragment_header_meta():
    with _session() as s:
        return render_template(
            "partials/_header_meta.html",
            latest_run=latest_run(s),
        )


@app.route("/fragments/overview")
def fragment_overview():
    with _session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_overview.html",
            latest_run=latest,
            runs_total=runs_total(s),
            verdict_counts=verdict_counts(s),
            judged_this_run=(judged_since(s, latest.started_at)
                             if latest else 0),
        )


@app.route("/fragments/sysint")
def fragment_sysint():
    with _session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_sysint.html",
            sysint=(system_integrity(s, latest.run_id) if latest else None),
        )


@app.route("/fragments/errors")
def fragment_errors():
    with _session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_errors.html",
            errors=(collector_errors(s, latest.run_id) if latest else []),
        )


@app.route("/fragments/findings")
def fragment_findings():
    verdict = request.args.get("verdict", "")
    with _session() as s:
        return render_template(
            "partials/_findings.html",
            findings=findings(s, verdict_filter=verdict or None),
            verdict_filter=verdict,
        )


@app.route("/fragments/row-counts")
def fragment_row_counts():
    with _session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_row_counts.html",
            row_counts=(row_counts(s, latest.started_at) if latest else []),
        )


@app.route("/fragments/runs")
def fragment_runs():
    with _session() as s:
        return render_template(
            "partials/_runs.html",
            recent_runs=recent_runs(s),
        )


@app.route("/api/chart/verdicts")
def api_chart_verdicts():
    with _session() as s:
        return jsonify(verdict_timeseries(s, hours=12))


# ============================================================================
# Entry point
# ============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="avai host monitor — single-page dashboard"
    )
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    app.config["DB_PATH"] = args.db
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


if __name__ == "__main__":
    sys.exit(main())
