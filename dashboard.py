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
from sqlalchemy import asc, case, create_engine, desc, func, or_, select
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
PER_PAGE_OPTIONS = (10, 25, 50, 100)
DEFAULT_PER_PAGE = 10

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "host_monitor.db"

app = Flask(__name__)
app.config["DB_PATH"] = str(DEFAULT_DB_PATH)


def _relative_time(iso_string: str) -> str:
    """Short relative-time string like '5m ago' for an ISO timestamp."""
    if not iso_string:
        return ""
    try:
        dt = datetime.fromisoformat(iso_string)
    except (ValueError, TypeError):
        return str(iso_string)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    seconds = int((datetime.now(timezone.utc) - dt).total_seconds())
    if seconds < 0:    return "just now"
    if seconds < 60:   return f"{seconds}s ago"
    if seconds < 3600: return f"{seconds // 60}m ago"
    if seconds < 86400: return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


app.add_template_filter(_relative_time, "relative_time")


def _pretty_json(value) -> str:
    """Re-serialize a JSON string with indentation. Pass non-JSON through."""
    if value in (None, "", b""):
        return ""
    try:
        return __import__("json").dumps(__import__("json").loads(value), indent=2)
    except Exception:
        return str(value)


app.add_template_filter(_pretty_json, "pretty_json")

# Columns hidden from the "all info" expansion (internal SQL plumbing).
_HIDDEN_SOURCE_FIELDS = {"id", "run_id"}


def _engine():
    return create_engine(f"sqlite:///{current_app.config['DB_PATH']}")


def _session() -> Session:
    return Session(_engine())


# ============================================================================
# Service layer — pure DB queries, no Flask
# ============================================================================

def latest_run(session: Session):
    """Most recent *completed* snapshot run.

    Aborted runs (the process was killed before ``end_run`` updated the
    counts) are excluded — they would show as 0/0 collectors and zero
    rows, which is misleading for "latest" displays. The full
    chronological list, including aborts, is still shown by
    ``recent_runs()``.
    """
    return session.execute(
        select(CollectionRun)
        .where(CollectionRun.finished_at.is_not(None))
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


def _row_and_artifact(session: Session, j: Judgement) -> tuple[dict, str]:
    """Return ``(source_row_dict, artifact_display_string)`` for a judgment.

    The source row is the *most recent* observation of the judgment's
    ``content_hash`` in its collector table (so we always show the
    latest state of the artifact, not the row from the run when it was
    first judged). Internal SQL plumbing columns are stripped.
    """
    model = COLLECTOR_MODELS.get(j.collector)
    if model is None:
        return {}, ""
    row_obj = session.execute(
        select(model)
        .where(model.content_hash == j.content_hash)
        .order_by(model.collected_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    if row_obj is None:
        return {}, ""
    full = {
        col.name: getattr(row_obj, col.name)
        for col in model.__table__.columns
        if col.name not in _HIDDEN_SOURCE_FIELDS
    }
    fields = DISPLAY_FIELDS.get(j.collector, ())
    artifact_parts = [str(full[f]) for f in fields
                      if full.get(f) is not None and full[f] != ""]
    return full, " · ".join(artifact_parts)


_SEVERITY_CASE = case(
    {"malicious": 0, "suspicious": 1, "unknown": 2, "benign": 3},
    value=Judgement.verdict,
    else_=99,
)

_SORT_FIELDS = {
    "severity":   _SEVERITY_CASE,
    "verdict":    Judgement.verdict,
    "collector":  Judgement.collector,
    "category":   Judgement.category,
    "confidence": Judgement.confidence,
    "judged":     Judgement.created_at,
}


def collector_options(session: Session) -> list[str]:
    rows = session.execute(
        select(Judgement.collector).distinct().order_by(Judgement.collector)
    ).all()
    return [r[0] for r in rows if r[0]]


def category_options(session: Session) -> list[str]:
    rows = session.execute(
        select(Judgement.category)
        .where(Judgement.category.is_not(None))
        .distinct()
        .order_by(Judgement.category)
    ).all()
    return [r[0] for r in rows if r[0]]


def findings(session: Session, *,
             verdict: str = "",
             collector: str = "",
             category: str = "",
             search: str = "",
             status: str = "active",
             sort: str = "severity",
             order: str = "desc",
             page: int = 1,
             per_page: int = DEFAULT_PER_PAGE) -> dict:
    """Paginated, filterable, sortable findings query.

    ``status`` is one of ``active`` / ``resolved`` / ``all``. A
    judgment is *active* if its ``last_seen_at`` matches the latest
    snapshot run's ``started_at``; otherwise (including NULL) it is
    *resolved* — the underlying artifact has gone away.

    Returns ``{items, total, page, per_page, total_pages,
                latest_started_at}``.
    """
    latest = latest_run(session)
    latest_started = latest.started_at if latest else None

    stmt = select(Judgement)

    if verdict and verdict in VERDICTS:
        stmt = stmt.where(Judgement.verdict == verdict)
    else:
        stmt = stmt.where(Judgement.verdict != "benign")
    if collector:
        stmt = stmt.where(Judgement.collector == collector)
    if category:
        stmt = stmt.where(Judgement.category == category)
    if search:
        like = f"%{search.lower()}%"
        stmt = stmt.where(or_(
            func.lower(Judgement.reasoning).like(like),
            func.lower(Judgement.remediation).like(like),
            func.lower(Judgement.collector).like(like),
            func.lower(Judgement.category).like(like),
        ))

    if latest_started and status == "active":
        stmt = stmt.where(Judgement.last_seen_at >= latest_started)
    elif latest_started and status == "resolved":
        stmt = stmt.where(or_(
            Judgement.last_seen_at < latest_started,
            Judgement.last_seen_at.is_(None),
        ))
    # status == "all" or no latest_run yet → no extra filter

    total = session.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar() or 0

    sort_col = _SORT_FIELDS.get(sort, _SEVERITY_CASE)
    if sort == "severity":
        # severity ascending + confidence descending is the natural pairing
        stmt = stmt.order_by(_SEVERITY_CASE.asc(),
                             Judgement.confidence.desc(),
                             Judgement.created_at.desc())
    else:
        direction = asc if order == "asc" else desc
        stmt = stmt.order_by(direction(sort_col), Judgement.created_at.desc())

    per_page = max(1, min(per_page, 200))
    page = max(1, page)
    stmt = stmt.offset((page - 1) * per_page).limit(per_page)

    raw = session.execute(stmt).scalars().all()
    items = []
    for j in raw:
        source_row, artifact = _row_and_artifact(session, j)
        is_active = bool(latest_started and j.last_seen_at
                         and j.last_seen_at >= latest_started)
        items.append({
            "verdict":      j.verdict,
            "collector":    j.collector,
            "category":     j.category or "none",
            "confidence":   j.confidence or 0.0,
            "reasoning":    j.reasoning or "",
            "remediation":  j.remediation or "",
            "created_at":   j.created_at,
            "last_seen_at": j.last_seen_at,
            "status":       "active" if is_active else "resolved",
            "artifact":     artifact,
            "source_row":   source_row,
            "content_hash": j.content_hash,
        })

    return {
        "items":             items,
        "total":             total,
        "page":              page,
        "per_page":          per_page,
        "total_pages":       max(1, (total + per_page - 1) // per_page),
        "latest_started_at": latest_started,
    }


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


def _int_arg(name: str, default: int) -> int:
    raw = request.args.get(name, "")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


@app.route("/fragments/findings")
def fragment_findings():
    verdict   = request.args.get("verdict", "")
    collector = request.args.get("collector", "")
    category  = request.args.get("category", "")
    search    = request.args.get("q", "")
    status    = request.args.get("status", "active")
    sort      = request.args.get("sort", "severity")
    order     = request.args.get("order", "desc")
    page      = _int_arg("page", 1)
    per_page  = _int_arg("per_page", DEFAULT_PER_PAGE)

    with _session() as s:
        result = findings(s, verdict=verdict, collector=collector,
                          category=category, search=search,
                          status=status,
                          sort=sort, order=order,
                          page=page, per_page=per_page)
        return render_template(
            "partials/_findings.html",
            findings=result["items"],
            total=result["total"],
            page=result["page"],
            per_page=result["per_page"],
            total_pages=result["total_pages"],
            verdict_filter=verdict,
            collector_filter=collector,
            category_filter=category,
            status_filter=status,
            q=search,
            sort=sort,
            order=order,
            collector_options=collector_options(s),
            category_options=category_options(s),
            per_page_options=PER_PAGE_OPTIONS,
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
