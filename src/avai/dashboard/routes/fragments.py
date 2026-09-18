"""HTML fragments the page polls with HTMX, plus the page itself."""

from __future__ import annotations

from flask import Blueprint, render_template, request
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from avai.host_monitor import CollectionRun

from ..control import monitor_alive, read_control_state
from ..queries import (
    DEFAULT_PER_PAGE,
    PER_PAGE_OPTIONS,
    FindingFilter,
    LogFilter,
    Page,
    PersistencePages,
    RowFilter,
    auth_events_aggregated,
    category_options,
    collector_errors,
    collector_options,
    cost_since,
    disk_usage,
    dns_queries,
    file_scan,
    findings,
    host_resources,
    judged_since,
    latest_narrative,
    latest_risk,
    latest_run,
    listening_ports,
    log_aggregates,
    log_entries,
    mount_tree,
    network_exposure,
    network_flows,
    network_topology,
    persistence_tampering,
    primary_filesystems,
    recent_runs,
    risk_trend,
    row_counts,
    runs_total,
    system_integrity,
    verdict_counts,
    vulnerabilities,
)
from ..queries.common import (
    _parse_json_list,
)
from . import read_session, services

bp = Blueprint("fragments", __name__)


@bp.route("/")
def index():
    return render_template("dashboard.html", app_mode=services().config.app_mode)


@bp.route("/fragments/triage")
def fragment_triage():
    """Above-the-fold triage strip: posture grade, active malicious/
    suspicious finding counts, and monitor liveness."""
    with read_session() as s:
        active_malicious = findings(
            s, filters=FindingFilter(verdict="malicious"), page=Page(1, 1)
        )["total"]
        active_suspicious = findings(
            s, filters=FindingFilter(verdict="suspicious"), page=Page(1, 1)
        )["total"]
        risk = latest_risk(s)
        state = read_control_state(s)  # reused for both alive and the ctrl chips
        return render_template(
            "partials/_triage.html",
            risk=risk,
            active_malicious=active_malicious,
            active_suspicious=active_suspicious,
            alive=monitor_alive(state),
            ctrl=state,
            latest_run=latest_run(s),
            drivers=_parse_json_list(getattr(risk, "drivers_json", None)),
            app_mode=services().config.app_mode,
        )


@bp.route("/fragments/header-meta")
def fragment_header_meta():
    with read_session() as s:
        return render_template(
            "partials/_header_meta.html",
            latest_run=latest_run(s),
        )


@bp.route("/fragments/overview")
def fragment_overview():
    with read_session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_overview.html",
            latest_run=latest,
            runs_total=runs_total(s),
            verdict_counts=verdict_counts(s),
            judged_this_run=(judged_since(s, latest.started_at) if latest else 0),
            cost_this_run=(cost_since(s, latest.started_at) if latest else 0.0),
        )


def _sparkline_points(scores: list, w: int = 140, h: int = 30, pad: int = 3) -> str:
    """SVG polyline points for a 0-100 score series (oldest→newest)."""
    if not scores:
        return ""
    pts = scores if len(scores) > 1 else scores * 2
    n = len(pts)
    span_x = (w - 2 * pad) / (n - 1)
    out = []
    for i, s in enumerate(pts):
        x = pad + i * span_x
        y = (h - pad) - (max(0, min(100, s)) / 100) * (h - 2 * pad)
        out.append(f"{x:.1f},{y:.1f}")
    return " ".join(out)


@bp.route("/fragments/risk")
def fragment_risk():
    with read_session() as s:
        row = latest_risk(s)
        drivers = _parse_json_list(getattr(row, "drivers_json", None)) if row else []
        trend = risk_trend(s)
        return render_template(
            "partials/_risk.html",
            risk=row,
            drivers=drivers,
            spark_points=_sparkline_points(trend),
            trend_len=len(trend),
        )


@bp.route("/fragments/incident")
def fragment_incident():
    with read_session() as s:
        row = latest_narrative(s)
        timeline = _parse_json_list(getattr(row, "timeline_json", None)) if row else []
        actions = _parse_json_list(getattr(row, "actions_json", None)) if row else []
        return render_template(
            "partials/_incident.html",
            narrative=row,
            timeline=timeline,
            actions=actions,
        )


@bp.route("/fragments/verdicts")
def fragment_verdicts():
    """Verdicts panel: last-12h activity trend. Cumulative totals live in
    the overview donut, so this panel no longer duplicates them."""
    return render_template("partials/_verdicts.html")


@bp.route("/fragments/posture")
def fragment_posture():
    """Merged posture panel: risk score + system-integrity checklist."""
    with read_session() as s:
        latest = latest_run(s)
        row = latest_risk(s)
        drivers = _parse_json_list(getattr(row, "drivers_json", None)) if row else []
        trend = risk_trend(s)
        return render_template(
            "partials/_posture.html",
            risk=row,
            drivers=drivers,
            spark_points=_sparkline_points(trend),
            trend_len=len(trend),
            sysint=(system_integrity(s, latest.run_id) if latest else None),
        )


@bp.route("/fragments/collection")
def fragment_collection():
    """Merged collection-health panel: row counts + recent runs + errors."""
    with read_session() as s:
        latest = latest_run(s)
        prid, pst = _prior_run(s, latest.started_at) if latest else (None, None)
        return render_template(
            "partials/_collection.html",
            recent_runs=recent_runs(s),
            errors=(collector_errors(s, latest.run_id) if latest else []),
            row_counts=(
                row_counts(s, latest.run_id, latest.started_at, prid, pst)
                if latest
                else []
            ),
        )


@bp.route("/fragments/network")
def fragment_network():
    """Tabbed network panel wrapper (tabs lazy-load the existing fragments)."""
    return render_template("partials/_network.html")


@bp.route("/fragments/vulnerabilities")
def fragment_vulnerabilities():
    """CVE / EOL 'protect yourself' panel from collected enrichment evidence."""
    q = request.args.get("q", "")
    severity = request.args.get("severity", "")
    source = request.args.get("source", "")
    page = _page_arg()
    with read_session() as s:
        return render_template(
            "partials/_vulnerabilities.html",
            vulns=vulnerabilities(
                s,
                q=q,
                severity=severity,
                source=source,
                page=page,
            ),
            per_page_options=PER_PAGE_OPTIONS,
        )


@bp.route("/fragments/sysint")
def fragment_sysint():
    with read_session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_sysint.html",
            sysint=(system_integrity(s, latest.run_id) if latest else None),
        )


@bp.route("/fragments/resources")
def fragment_resources():
    """System-resources panel: current memory/swap/CPU/load/uptime/tasks +
    per-filesystem disk tree + trend-chart canvases."""
    with read_session() as s:
        latest = latest_run(s)
        disks = disk_usage(s, latest.run_id) if latest else []
        return render_template(
            "partials/_resources.html",
            resources=(host_resources(s, latest.run_id) if latest else None),
            disks_primary=primary_filesystems(disks),
            mounts=mount_tree(disks),
        )


@bp.route("/fragments/network-flows")
def fragment_network_flows():
    verdict = request.args.get("verdict", "")
    q = request.args.get("q", "")
    page = _page_arg()
    with read_session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_network_flows.html",
            flows=(
                network_flows(
                    s, latest.run_id, filters=RowFilter(verdict, q), page=page
                )
                if latest
                else None
            ),
            per_page_options=PER_PAGE_OPTIONS,
        )


@bp.route("/fragments/listening-ports")
def fragment_listening_ports():
    verdict = request.args.get("verdict", "")
    scope_filter = request.args.get("scope_filter", "")
    q = request.args.get("q", "")
    page = _page_arg()
    with read_session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_listening_ports.html",
            ports=(
                listening_ports(
                    s,
                    latest.run_id,
                    filters=RowFilter(verdict, q),
                    scope_filter=scope_filter,
                    page=page,
                )
                if latest
                else None
            ),
            per_page_options=PER_PAGE_OPTIONS,
        )


@bp.route("/fragments/dns-queries")
def fragment_dns_queries():
    verdict = request.args.get("verdict", "")
    level = request.args.get("level", "")
    q = request.args.get("q", "")
    page = _page_arg()
    with read_session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_dns_queries.html",
            dns=(
                dns_queries(
                    s,
                    latest.run_id,
                    filters=RowFilter(verdict, q),
                    level=level,
                    page=page,
                )
                if latest
                else None
            ),
            per_page_options=PER_PAGE_OPTIONS,
        )


@bp.route("/fragments/log-summary")
def fragment_log_summary():
    group_by = request.args.get("group_by", "unit")
    source = request.args.get("source", "")
    q = request.args.get("q", "")
    page = _page_arg()
    with read_session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_log_summary.html",
            summary=(
                log_aggregates(
                    s,
                    latest.run_id,
                    filters=LogFilter(source=source, q=q),
                    group_by=group_by,
                    page=page,
                )
                if latest
                else None
            ),
            per_page_options=PER_PAGE_OPTIONS,
        )


@bp.route("/fragments/logs")
def fragment_logs():
    source = request.args.get("source", "")
    level = request.args.get("level", "")
    q = request.args.get("q", "")
    page = _page_arg()
    with read_session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_logs.html",
            logs=(
                log_entries(
                    s,
                    latest.run_id,
                    filters=LogFilter(source, level, q),
                    page=page,
                )
                if latest
                else None
            ),
            per_page_options=PER_PAGE_OPTIONS,
        )


@bp.route("/fragments/network-topology")
def fragment_network_topology():
    verdict = request.args.get("verdict", "")
    q = request.args.get("q", "")
    with read_session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_network_topology.html",
            topo=(
                network_topology(s, latest.run_id, filters=RowFilter(verdict, q))
                if latest
                else None
            ),
        )


@bp.route("/fragments/network-exposure")
def fragment_network_exposure():
    verdict = request.args.get("verdict", "")
    q = request.args.get("q", "")
    with read_session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_network_exposure.html",
            expo=(
                network_exposure(s, latest.run_id, filters=RowFilter(verdict, q))
                if latest
                else None
            ),
        )


@bp.route("/fragments/persistence")
def fragment_persistence():
    verdict = request.args.get("verdict", "")
    q = request.args.get("q", "")
    pages = PersistencePages(
        ssh=_page_arg("ssh_page"),
        hosts=_page_arg("hosts_page"),
        priv=_page_arg("priv_page"),
    )
    with read_session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_persistence.html",
            data=(
                persistence_tampering(
                    s,
                    latest.run_id,
                    filters=RowFilter(verdict, q),
                    pages=pages,
                )
                if latest
                else None
            ),
            per_page_options=PER_PAGE_OPTIONS,
        )


@bp.route("/fragments/auth-events")
def fragment_auth_events():
    q = request.args.get("q", "")
    subsystem = request.args.get("subsystem", "")
    verdict = request.args.get("verdict", "")
    sort = request.args.get("sort", "count")
    page = _page_arg()
    with read_session() as s:
        return render_template(
            "partials/_auth_events.html",
            events=auth_events_aggregated(
                s,
                filters=RowFilter(verdict, q),
                subsystem=subsystem,
                sort=sort,
                page=page,
            ),
            per_page_options=PER_PAGE_OPTIONS,
        )


@bp.route("/fragments/errors")
def fragment_errors():
    with read_session() as s:
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


def _page_arg(name: str = "page") -> Page:
    return Page(_int_arg(name, 1), _int_arg("per_page", DEFAULT_PER_PAGE))


@bp.route("/fragments/findings")
def fragment_findings():
    verdict = request.args.get("verdict", "")
    collector = request.args.get("collector", "")
    category = request.args.get("category", "")
    search = request.args.get("q", "")
    status = request.args.get("status", "active")
    sort = request.args.get("sort", "severity")
    order = request.args.get("order", "desc")
    page = _page_arg()

    with read_session() as s:
        result = findings(
            s,
            filters=FindingFilter(verdict, collector, category, search, status),
            sort=sort,
            order=order,
            page=page,
        )
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


@bp.route("/fragments/file-scan")
def fragment_file_scan():
    verdict = request.args.get("verdict", "")
    q = request.args.get("q", "")
    with read_session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_file_scan.html",
            data=(
                file_scan(s, latest.run_id, filters=RowFilter(verdict, q))
                if latest
                else None
            ),
        )


@bp.route("/fragments/row-counts")
def fragment_row_counts():
    with read_session() as s:
        latest = latest_run(s)
        if latest is None:
            return render_template("partials/_row_counts.html", row_counts=[])
        prid, pst = _prior_run(s, latest.started_at)
        return render_template(
            "partials/_row_counts.html",
            row_counts=row_counts(s, latest.run_id, latest.started_at, prid, pst),
        )


def _prior_run(session: Session, before_started: str) -> tuple[str | None, str | None]:
    """``(run_id, started_at)`` of the run immediately before
    ``before_started``, or ``(None, None)`` if it's the first run."""
    row = session.execute(
        select(CollectionRun.run_id, CollectionRun.started_at)
        .where(CollectionRun.started_at < before_started)
        .order_by(desc(CollectionRun.started_at))
        .limit(1)
    ).first()
    return (row[0], row[1]) if row else (None, None)


@bp.route("/fragments/runs")
def fragment_runs():
    with read_session() as s:
        return render_template(
            "partials/_runs.html",
            recent_runs=recent_runs(s),
        )
