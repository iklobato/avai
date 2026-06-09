"""Flask app, config, Jinja template filters, and all HTTP routes."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from avai.host_monitor import CollectionRun

from .queries import (
    DEFAULT_DB_PATH,
    DEFAULT_PER_PAGE,
    PER_PAGE_OPTIONS,
    _parse_json_list,
    _session,
    auth_events_aggregated,
    category_options,
    collector_errors,
    collector_options,
    cost_since,
    disk_usage,
    dns_queries,
    findings,
    host_resources,
    judged_since,
    latest_narrative,
    latest_risk,
    latest_run,
    listening_ports,
    network_flows,
    new_alerts,
    persistence_tampering,
    recent_runs,
    resource_trend,
    risk_trend,
    row_counts,
    runs_total,
    system_integrity,
    verdict_counts,
    verdict_timeseries,
    vulnerabilities,
)

_PKG_DIR = Path(__file__).resolve().parent.parent


app = Flask(
    __name__,
    template_folder=str(_PKG_DIR / "templates"),
    static_folder=str(_PKG_DIR / "static"),
)


app.config["DB_PATH"] = str(DEFAULT_DB_PATH)


app.config["TEMPLATES_AUTO_RELOAD"] = True


app.jinja_env.auto_reload = True


try:
    import bleach as _bleach
    import markdown as _markdown

    _HAS_MARKDOWN = True
except ImportError:  # pragma: no cover - depends on optional extras
    _HAS_MARKDOWN = False


_MD_TAGS = [
    "p",
    "br",
    "strong",
    "em",
    "code",
    "pre",
    "blockquote",
    "hr",
    "ul",
    "ol",
    "li",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
]


_LIST_ITEM_RE = re.compile(r"^\s*([-*+]\s+|\d+[.)]\s+)")


def _ensure_list_blank_lines(text: str) -> str:
    """Insert a blank line before a list that directly follows a non-list
    text line. The narrator (like most LLMs) writes ``**Timeline:**`` then a
    ``- item`` bullet on the very next line; python-markdown won't treat a
    list as interrupting a paragraph without a preceding blank line, so
    without this the bullets render as literal ``- `` text."""
    out: list[str] = []
    prev = ""
    for line in text.split("\n"):
        is_item = bool(_LIST_ITEM_RE.match(line))
        if (
            is_item
            and prev.strip()
            and not _LIST_ITEM_RE.match(prev)
            and not prev.lstrip().startswith("```")
        ):
            out.append("")
        out.append(line)
        prev = line
    return "\n".join(out)


def render_markdown(text: str) -> str:
    """LLM-written markdown → sanitised HTML. Falls back to HTML-escaped
    text (newlines preserved via CSS) when the optional libs are missing."""
    from markupsafe import Markup, escape

    if not text:
        return Markup("")
    if not _HAS_MARKDOWN:
        return Markup(f'<div class="whitespace-pre-line">{escape(text)}</div>')
    html = _markdown.markdown(
        _ensure_list_blank_lines(text),
        extensions=["fenced_code", "tables", "sane_lists"],
    )
    clean = _bleach.clean(html, tags=_MD_TAGS, attributes={}, strip=True)
    return Markup(clean)


app.add_template_filter(render_markdown, "markdown")


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
    if seconds < 0:
        return "just now"
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


app.add_template_filter(_relative_time, "relative_time")


def _datetime_fmt(iso_string: str) -> str:
    """Human-readable absolute timestamp (UTC) like 'May 30, 2026 · 18:57:20
    UTC' from a stored ISO string. Returns the input unchanged if it isn't a
    parseable timestamp, and '' for empty input."""
    if not iso_string:
        return ""
    try:
        dt = datetime.fromisoformat(iso_string)
    except (ValueError, TypeError):
        return str(iso_string)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%b %d, %Y · %H:%M:%S UTC")


app.add_template_filter(_datetime_fmt, "datetime_fmt")


def _pretty_json(value) -> str:
    """Re-serialize a JSON string with indentation. Pass non-JSON through."""
    if value in (None, "", b""):
        return ""
    try:
        return __import__("json").dumps(__import__("json").loads(value), indent=2)
    except Exception:
        return str(value)


def _human_bytes(n) -> str:
    """Human-readable data volume (e.g. 927 -> '927 B', 12345 -> '12.1 KB',
    5e6 -> '4.8 MB'). Returns '' for 0/None/unknown so the template can
    fall back to a packet count."""
    if not isinstance(n, (int, float)) or n <= 0:
        return ""
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return ""


app.add_template_filter(_human_bytes, "human_bytes")


def _flag_emoji(cc) -> str:
    """Render a 2-letter ISO country code as its flag emoji (regional
    indicator symbols), e.g. 'US' -> 🇺🇸. Empty string for anything that
    isn't a clean 2-letter code."""
    if not isinstance(cc, str) or len(cc) != 2 or not cc.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in cc.upper())


app.add_template_filter(_flag_emoji, "flag_emoji")


app.add_template_filter(_pretty_json, "pretty_json")


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


@app.route("/fragments/risk")
def fragment_risk():
    with _session() as s:
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


@app.route("/fragments/incident")
def fragment_incident():
    with _session() as s:
        row = latest_narrative(s)
        timeline = _parse_json_list(getattr(row, "timeline_json", None)) if row else []
        actions = _parse_json_list(getattr(row, "actions_json", None)) if row else []
        return render_template(
            "partials/_incident.html",
            narrative=row,
            timeline=timeline,
            actions=actions,
        )


@app.route("/fragments/verdicts")
def fragment_verdicts():
    """Merged verdicts panel: all-time totals donut + last-12h trend."""
    with _session() as s:
        return render_template(
            "partials/_verdicts.html", verdict_counts=verdict_counts(s)
        )


@app.route("/fragments/posture")
def fragment_posture():
    """Merged posture panel: risk score + system-integrity checklist."""
    with _session() as s:
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


@app.route("/fragments/collection")
def fragment_collection():
    """Merged collection-health panel: row counts + recent runs + errors."""
    with _session() as s:
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


@app.route("/fragments/network")
def fragment_network():
    """Tabbed network panel wrapper (tabs lazy-load the existing fragments)."""
    return render_template("partials/_network.html")


@app.route("/fragments/vulnerabilities")
def fragment_vulnerabilities():
    """CVE / EOL 'protect yourself' panel from collected enrichment evidence."""
    with _session() as s:
        return render_template(
            "partials/_vulnerabilities.html", vulns=vulnerabilities(s)
        )


@app.route("/fragments/sysint")
def fragment_sysint():
    with _session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_sysint.html",
            sysint=(system_integrity(s, latest.run_id) if latest else None),
        )


@app.route("/fragments/resources")
def fragment_resources():
    """System-resources panel: current memory/swap/CPU/load/uptime/tasks +
    per-filesystem disk table + trend-chart canvases."""
    with _session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_resources.html",
            resources=(host_resources(s, latest.run_id) if latest else None),
            disks=(disk_usage(s, latest.run_id) if latest else []),
        )


@app.route("/fragments/network-flows")
def fragment_network_flows():
    verdict = request.args.get("verdict", "")
    q = request.args.get("q", "")
    page = _int_arg("page", 1)
    per_page = _int_arg("per_page", DEFAULT_PER_PAGE)
    with _session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_network_flows.html",
            flows=(
                network_flows(
                    s, latest.run_id, verdict=verdict, q=q, page=page, per_page=per_page
                )
                if latest
                else None
            ),
            per_page_options=PER_PAGE_OPTIONS,
        )


@app.route("/fragments/listening-ports")
def fragment_listening_ports():
    verdict = request.args.get("verdict", "")
    scope_filter = request.args.get("scope_filter", "")
    q = request.args.get("q", "")
    page = _int_arg("page", 1)
    per_page = _int_arg("per_page", DEFAULT_PER_PAGE)
    with _session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_listening_ports.html",
            ports=(
                listening_ports(
                    s,
                    latest.run_id,
                    verdict=verdict,
                    scope_filter=scope_filter,
                    q=q,
                    page=page,
                    per_page=per_page,
                )
                if latest
                else None
            ),
            per_page_options=PER_PAGE_OPTIONS,
        )


@app.route("/fragments/dns-queries")
def fragment_dns_queries():
    verdict = request.args.get("verdict", "")
    level = request.args.get("level", "")
    q = request.args.get("q", "")
    page = _int_arg("page", 1)
    per_page = _int_arg("per_page", DEFAULT_PER_PAGE)
    with _session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_dns_queries.html",
            dns=(
                dns_queries(
                    s,
                    latest.run_id,
                    verdict=verdict,
                    level=level,
                    q=q,
                    page=page,
                    per_page=per_page,
                )
                if latest
                else None
            ),
            per_page_options=PER_PAGE_OPTIONS,
        )


@app.route("/fragments/persistence")
def fragment_persistence():
    verdict = request.args.get("verdict", "")
    q = request.args.get("q", "")
    ssh_page = _int_arg("ssh_page", 1)
    hosts_page = _int_arg("hosts_page", 1)
    priv_page = _int_arg("priv_page", 1)
    per_page = _int_arg("per_page", DEFAULT_PER_PAGE)
    with _session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_persistence.html",
            data=(
                persistence_tampering(
                    s,
                    latest.run_id,
                    verdict=verdict,
                    q=q,
                    ssh_page=ssh_page,
                    hosts_page=hosts_page,
                    priv_page=priv_page,
                    per_page=per_page,
                )
                if latest
                else None
            ),
            per_page_options=PER_PAGE_OPTIONS,
        )


@app.route("/fragments/auth-events")
def fragment_auth_events():
    q = request.args.get("q", "")
    subsystem = request.args.get("subsystem", "")
    verdict = request.args.get("verdict", "")
    sort = request.args.get("sort", "count")
    page = _int_arg("page", 1)
    per_page = _int_arg("per_page", DEFAULT_PER_PAGE)
    with _session() as s:
        return render_template(
            "partials/_auth_events.html",
            events=auth_events_aggregated(
                s,
                q=q,
                subsystem=subsystem,
                verdict=verdict,
                sort=sort,
                page=page,
                per_page=per_page,
            ),
            per_page_options=PER_PAGE_OPTIONS,
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
    verdict = request.args.get("verdict", "")
    collector = request.args.get("collector", "")
    category = request.args.get("category", "")
    search = request.args.get("q", "")
    status = request.args.get("status", "active")
    sort = request.args.get("sort", "severity")
    order = request.args.get("order", "desc")
    page = _int_arg("page", 1)
    per_page = _int_arg("per_page", DEFAULT_PER_PAGE)

    with _session() as s:
        result = findings(
            s,
            verdict=verdict,
            collector=collector,
            category=category,
            search=search,
            status=status,
            sort=sort,
            order=order,
            page=page,
            per_page=per_page,
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


@app.route("/fragments/row-counts")
def fragment_row_counts():
    with _session() as s:
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


@app.route("/api/chart/resources")
def api_chart_resources():
    """Memory / CPU / swap percentage time-series for the resource trend
    charts (latest N runs)."""
    with _session() as s:
        return jsonify(resource_trend(s))


@app.route("/api/notifications/new")
def api_notifications_new():
    """Return malicious/suspicious judgements created after ``?since``.
    The client supplies its last-seen timestamp (persisted in
    localStorage). The response also includes ``now`` so the client can
    advance its cursor even when there are no new items, avoiding
    re-alerting on the same gap if the timestamp ever changed."""
    since = request.args.get("since", "")
    with _session() as s:
        items = new_alerts(s, since=since or None)
    return jsonify(
        {
            "since": since,
            "items": items,
            "now": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
    )
