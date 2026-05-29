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
import ipaddress
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, current_app, jsonify, render_template, request
from sqlalchemy import (
    and_,
    asc,
    case,
    create_engine,
    desc,
    func,
    literal,
    or_,
    select,
    text,
)
from sqlalchemy.orm import Session

# Reuse models from host_monitor.py — single source of schema truth.
from avai.host_monitor import Base  # noqa: E402
from avai.host_monitor import (
    AuthEventRow,
    BluetoothDeviceRow,
    BrowserExtensionRow,
    CollectionRun,
    CollectorErrorRow,
    DnsQueryRow,
    FileIntegrityRow,
    HostsFileRow,
    InstalledAppRow,
    Judgement,
    KernelExtensionRow,
    LaunchItemRow,
    ListeningPortRow,
    MdmProfileRow,
    MountRow,
    NetworkConnectionRow,
    NetworkFlowRow,
    NetworkInterfaceRow,
    PrivilegeConfigRow,
    ProcessExecRow,
    ProcessRow,
    QuarantineEventRow,
    SetuidFileRow,
    SshAuthorizedKeyRow,
    SystemExtensionRow,
    SystemIntegrityRow,
    TccPermissionRow,
    UsbDeviceRow,
    WifiStateRow,
)

COLLECTOR_MODELS = {
    "processes": ProcessRow,
    "network_connections": NetworkConnectionRow,
    "network_flows": NetworkFlowRow,
    "dns_queries": DnsQueryRow,
    "ssh_authorized_keys": SshAuthorizedKeyRow,
    "hosts_file": HostsFileRow,
    "privilege_config": PrivilegeConfigRow,
    "listening_ports": ListeningPortRow,
    "network_interfaces": NetworkInterfaceRow,
    "usb_devices": UsbDeviceRow,
    "bluetooth_devices": BluetoothDeviceRow,
    "wifi_state": WifiStateRow,
    "launch_items": LaunchItemRow,
    "tcc_permissions": TccPermissionRow,
    "quarantine_events": QuarantineEventRow,
    "browser_extensions": BrowserExtensionRow,
    "system_integrity": SystemIntegrityRow,
    "auth_events": AuthEventRow,
    "file_integrity": FileIntegrityRow,
    "installed_apps": InstalledAppRow,
    # Phase 4
    "process_exec_events": ProcessExecRow,
    "mounts": MountRow,
    "setuid_files": SetuidFileRow,
    "mdm_profiles": MdmProfileRow,
    "kernel_extensions": KernelExtensionRow,
    "system_extensions": SystemExtensionRow,
}

DISPLAY_FIELDS: dict[str, tuple[str, ...]] = {
    "processes": ("name", "exe"),
    "network_flows": ("dst_ip", "dst_port"),
    "dns_queries": ("qname", "qtype"),
    "ssh_authorized_keys": ("owner", "fingerprint"),
    "hosts_file": ("ip", "hostnames"),
    "privilege_config": ("kind", "subject"),
    "listening_ports": ("process_name", "laddr_port"),
    "usb_devices": ("name", "manufacturer"),
    "bluetooth_devices": ("name",),
    "wifi_state": ("ssid",),
    "launch_items": ("label", "path"),
    "tcc_permissions": ("client", "service"),
    "quarantine_events": ("agent_name", "origin_url"),
    "browser_extensions": ("name", "browser"),
    "system_integrity": (),
    "file_integrity": ("path",),
    "installed_apps": ("name", "bundle_id"),
    # Phase 4
    "process_exec_events": ("exe_path", "parent_path"),
    "mounts": ("mountpoint", "device", "fstype"),
    "setuid_files": ("path",),
    "mdm_profiles": ("display_name", "organization"),
    "kernel_extensions": ("bundle_id", "name"),
    "system_extensions": ("bundle_id", "team_id"),
}

SEVERITY_ORDER = {"malicious": 0, "suspicious": 1, "unknown": 2, "benign": 3}
VERDICTS = ("malicious", "suspicious", "unknown", "benign")
PER_PAGE_OPTIONS = (10, 25, 50, 100)
DEFAULT_PER_PAGE = 10

# Default DB lives in the current working directory so the pip-
# installed `avai dashboard` doesn't try to read from site-packages.
# Override at runtime with --db or by setting app.config["DB_PATH"].
DEFAULT_DB_PATH = Path.cwd() / "avai.db"

# Templates and static assets ship inside the installed package
# (src/avai/templates/, src/avai/static/). Flask defaults to looking
# in <module>/templates and <module>/static, but we set them
# explicitly here so the path is unambiguous regardless of how the
# module is invoked (entry-point script, `python -m avai.dashboard`,
# Docker CMD, etc.).
_PKG_DIR = Path(__file__).resolve().parent

app = Flask(
    __name__,
    template_folder=str(_PKG_DIR / "templates"),
    static_folder=str(_PKG_DIR / "static"),
)
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

# Columns hidden from the "all info" expansion (internal SQL plumbing).
_HIDDEN_SOURCE_FIELDS = {"id", "run_id"}


def _engine():
    """Open the SQLite database read-only (``mode=ro``).

    The dashboard never writes; the monitor maintains the WAL.

    We deliberately do NOT pass ``immutable=1``. ``immutable=1`` tells
    SQLite the file is a frozen snapshot and to ignore the ``-wal``
    file — which means the reader sees only data already checkpointed
    into the main ``.db``. On a live database that the monitor is
    actively writing (and especially in the first seconds before the
    very first WAL checkpoint), the schema + rows live in the ``-wal``,
    so ``immutable=1`` reads an empty/incomplete database and every
    query 500s with "no such table". ``mode=ro`` reads the WAL
    correctly, so the dashboard sees live data immediately.

    ``_engine()`` is called fresh per request, so each refresh sees the
    latest committed state.
    """
    db_path = current_app.config["DB_PATH"]
    return create_engine(
        f"sqlite:///file:{db_path}?mode=ro&uri=true",
    )


def _session() -> Session:
    return Session(_engine())


# ============================================================================
# Service layer — pure DB queries, no Flask
# ============================================================================


def _existing_tables(session: Session) -> set[str]:
    """Tables actually present in the DB. The dashboard may read a
    database written by an *older* monitor that predates a collector
    (e.g. network_flows), so querying a not-yet-created table would 500.
    Callers check membership here and degrade gracefully instead."""
    return set(
        session.execute(
            text("SELECT name FROM sqlite_master WHERE type='table'")
        ).scalars()
    )


def _existing_columns(session: Session, table: str) -> set[str]:
    """Column names present on ``table``. The DB may have been written by
    an older monitor missing a newly-added column (e.g. network_flows.
    iface); selecting it would 500. Callers substitute a NULL literal
    for absent columns instead."""
    rows = session.execute(text(f"PRAGMA table_info({table})")).all()
    return {r[1] for r in rows}  # row[1] is the column name


def latest_run(session: Session):
    """The run the dashboard should display.

    Prefer the most recent *completed* run (a consistent, fully
    populated snapshot — and no flicker to empty when the next cycle
    starts). But if nothing has completed yet — the common first-run
    case, where the monitor is still grinding through its first cycle
    (collectors + LLM judging take minutes) — fall back to the most
    recent in-progress run so the dashboard shows live, partial data
    instead of "no run yet". Otherwise the user stares at an empty
    page for the entire first cycle.
    """
    completed = session.execute(
        select(CollectionRun)
        .where(CollectionRun.finished_at.is_not(None))
        .order_by(desc(CollectionRun.started_at))
        .limit(1)
    ).scalar_one_or_none()
    if completed is not None:
        return completed
    # No completed run yet → show the latest in-progress one.
    return session.execute(
        select(CollectionRun).order_by(desc(CollectionRun.started_at)).limit(1)
    ).scalar_one_or_none()


def recent_runs(session: Session, limit: int = 10) -> list[CollectionRun]:
    return list(
        session.execute(
            select(CollectionRun).order_by(desc(CollectionRun.started_at)).limit(limit)
        ).scalars()
    )


def runs_total(session: Session) -> int:
    return (
        session.execute(select(func.count()).select_from(CollectionRun)).scalar() or 0
    )


def verdict_counts(session: Session) -> dict[str, int]:
    return dict(
        session.execute(
            select(Judgement.verdict, func.count(Judgement.content_hash)).group_by(
                Judgement.verdict
            )
        ).all()
    )


def judged_since(session: Session, since: str) -> int:
    return (
        session.execute(
            select(func.count(Judgement.content_hash)).where(
                Judgement.created_at >= since
            )
        ).scalar()
        or 0
    )


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
    artifact_parts = [
        str(full[f]) for f in fields if full.get(f) is not None and full[f] != ""
    ]
    return full, " · ".join(artifact_parts)


_SEVERITY_CASE = case(
    {"malicious": 0, "suspicious": 1, "unknown": 2, "benign": 3},
    value=Judgement.verdict,
    else_=99,
)

_SORT_FIELDS = {
    "severity": _SEVERITY_CASE,
    "verdict": Judgement.verdict,
    "collector": Judgement.collector,
    "category": Judgement.category,
    "confidence": Judgement.confidence,
    "judged": Judgement.created_at,
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


def findings(
    session: Session,
    *,
    verdict: str = "",
    collector: str = "",
    category: str = "",
    search: str = "",
    status: str = "active",
    sort: str = "severity",
    order: str = "desc",
    page: int = 1,
    per_page: int = DEFAULT_PER_PAGE,
) -> dict:
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
        stmt = stmt.where(
            or_(
                func.lower(Judgement.reasoning).like(like),
                func.lower(Judgement.remediation).like(like),
                func.lower(Judgement.collector).like(like),
                func.lower(Judgement.category).like(like),
            )
        )

    if latest_started and status == "active":
        stmt = stmt.where(Judgement.last_seen_at >= latest_started)
    elif latest_started and status == "resolved":
        stmt = stmt.where(
            or_(
                Judgement.last_seen_at < latest_started,
                Judgement.last_seen_at.is_(None),
            )
        )
    # status == "all" or no latest_run yet → no extra filter

    total = (
        session.execute(select(func.count()).select_from(stmt.subquery())).scalar() or 0
    )

    sort_col = _SORT_FIELDS.get(sort, _SEVERITY_CASE)
    if sort == "severity":
        # severity ascending + confidence descending is the natural pairing
        stmt = stmt.order_by(
            _SEVERITY_CASE.asc(),
            Judgement.confidence.desc(),
            Judgement.created_at.desc(),
        )
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
        is_active = bool(
            latest_started and j.last_seen_at and j.last_seen_at >= latest_started
        )
        items.append(
            {
                "verdict": j.verdict,
                "collector": j.collector,
                "category": j.category or "none",
                "confidence": j.confidence or 0.0,
                "reasoning": j.reasoning or "",
                "remediation": j.remediation or "",
                "created_at": j.created_at,
                "last_seen_at": j.last_seen_at,
                "status": "active" if is_active else "resolved",
                "artifact": artifact,
                "source_row": source_row,
                "content_hash": j.content_hash,
            }
        )

    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
        "latest_started_at": latest_started,
    }


def row_counts(session: Session, since: str) -> list[dict]:
    out = []
    present = _existing_tables(session)
    for name, model in COLLECTOR_MODELS.items():
        # Skip tables an older monitor never created — querying them
        # would raise "no such table" and 500 the whole panel.
        if model.__tablename__ not in present:
            continue
        n = (
            session.execute(
                select(func.count())
                .select_from(model)
                .where(model.collected_at >= since)
            ).scalar()
            or 0
        )
        out.append({"name": name, "rows": n})
    out.sort(key=lambda x: x["rows"], reverse=True)
    return out


def collector_errors(session: Session, run_id: str) -> list[CollectorErrorRow]:
    return list(
        session.execute(
            select(CollectorErrorRow).where(CollectorErrorRow.run_id == run_id)
        ).scalars()
    )


# Verdict severity for "worst-first" ordering. Unjudged flows (None)
# sort last so judged risk floats to the top.
_FLOW_SEV = {"malicious": 0, "suspicious": 1, "unknown": 2, "benign": 3, None: 4}


def network_flows(session: Session, run_id: str, limit: int = 1000):
    """Tcpdump flows for ``run_id``, **aggregated by destination IP** for
    a compact, glanceable table.

    Each raw flow is one (iface, proto, dst_ip, dst_port) with a packet
    count and (LEFT JOIN) its LLM verdict. We roll those up per dst_ip:
    SUM(packets), COUNT(flows), the set of interfaces / protocols /
    ports, and the worst verdict among the destination's flows. Returns
    ``{"summary": {...}, "rows": [...]}`` with rows worst-verdict first
    then by total packets.

    Degrades to empty if the network_flows table doesn't exist yet
    (DB written by a monitor that predates this collector)."""
    empty = {
        "summary": {
            "destinations": 0,
            "flows": 0,
            "packets": 0,
            "malicious": 0,
            "suspicious": 0,
        },
        "rows": [],
    }
    if "network_flows" not in _existing_tables(session):
        return empty

    # Tolerate a network_flows table written by an older monitor that
    # lacks newer columns (iface / service) — substitute a NULL literal
    # so the SELECT doesn't 500 on "no such column".
    cols = _existing_columns(session, "network_flows")
    iface_sel = (
        NetworkFlowRow.iface if "iface" in cols else literal(None).label("iface")
    )
    service_sel = (
        NetworkFlowRow.service if "service" in cols else literal(None).label("service")
    )
    process_sel = (
        NetworkFlowRow.process if "process" in cols else literal(None).label("process")
    )
    bytes_sel = (
        NetworkFlowRow.byte_count
        if "byte_count" in cols
        else literal(None).label("byte_count")
    )

    stmt = (
        select(
            iface_sel,
            NetworkFlowRow.proto,
            NetworkFlowRow.dst_ip,
            NetworkFlowRow.dst_port,
            service_sel,
            NetworkFlowRow.packets,
            bytes_sel,
            process_sel,
            Judgement.verdict,
            Judgement.confidence,
            Judgement.reasoning,
        )
        .outerjoin(
            Judgement,
            and_(
                Judgement.content_hash == NetworkFlowRow.content_hash,
                Judgement.collector == "network_flows",
            ),
        )
        .where(NetworkFlowRow.run_id == run_id)
        .limit(limit)
    )

    groups: dict[str, dict] = {}
    for (
        iface,
        proto,
        dst_ip,
        dst_port,
        service,
        packets,
        byte_count,
        process,
        verdict,
        conf,
        reason,
    ) in session.execute(stmt).all():
        g = groups.get(dst_ip)
        if g is None:
            g = groups[dst_ip] = {
                "dst_ip": dst_ip,
                "packets": 0,
                "bytes": 0,
                "flows": 0,
                "_ifaces": set(),
                "_protos": set(),
                "_ports": set(),
                "_procs": set(),
                "verdict": None,
                "confidence": None,
                "reasoning": "",
            }
        g["packets"] += packets or 0
        g["bytes"] += byte_count or 0
        g["flows"] += 1
        if iface:
            g["_ifaces"].add(iface)
        if proto:
            g["_protos"].add(proto)
        if process:
            g["_procs"].add(process)
        if dst_port is not None:
            g["_ports"].add(f"{dst_port}/{service}" if service else str(dst_port))
        # Keep the worst (lowest-severity-number) verdict + its reasoning.
        if _FLOW_SEV.get(verdict, 4) < _FLOW_SEV.get(g["verdict"], 4):
            g["verdict"] = verdict
            g["confidence"] = conf
            g["reasoning"] = reason or ""

    rows = []
    for g in groups.values():
        rows.append(
            {
                "dst_ip": g["dst_ip"],
                "iface": ", ".join(sorted(g["_ifaces"])) or "—",
                "proto": [p.upper() for p in sorted(g["_protos"])],
                "ports": sorted(g["_ports"], key=_port_sort_key),
                "process": ", ".join(sorted(g["_procs"])) or "—",
                "packets": g["packets"],
                "bytes": g["bytes"],
                "flows": g["flows"],
                "verdict": g["verdict"],
                "confidence": g["confidence"],
                "reasoning": g["reasoning"],
                "geo": None,  # filled below from the enrichment cache
                "hostname": None,  # filled below from the enrichment cache
            }
        )

    # Attach geolocation + resolved hostname per destination IP from the
    # enrichment_evidence cache the monitor already populated (ipwho.is
    # geo, Shodan/AbuseIPDB hostnames, AbuseIPDB/Feodo geo fallbacks).
    _attach_ip_enrichment(session, rows)

    rows.sort(key=lambda r: (_FLOW_SEV.get(r["verdict"], 4), -r["packets"]))

    summary = {
        "destinations": len(rows),
        "flows": sum(r["flows"] for r in rows),
        "packets": sum(r["packets"] for r in rows),
        "bytes": sum(r["bytes"] for r in rows),
        "malicious": sum(1 for r in rows if r["verdict"] == "malicious"),
        "suspicious": sum(1 for r in rows if r["verdict"] == "suspicious"),
    }
    return {"summary": summary, "rows": rows}


def _port_sort_key(p: str):
    """Sort '443/https' or '4444' numerically by the leading port."""
    head = p.split("/", 1)[0]
    return int(head) if head.isdigit() else 0


def _geo_from_details(details: dict) -> dict | None:
    """Extract a normalised geolocation from one evidence row's details,
    tolerating each source's own key names: ipwho.is
    (country/city/region/asn/org), AbuseIPDB (countryCode/isp), Feodo
    (country/as_name/as_number). Returns ``None`` when the row carries no
    geo at all."""
    cc = details.get("country_code") or details.get("countryCode")
    country = details.get("country") or cc
    city = details.get("city")
    region = details.get("region")
    org = details.get("org") or details.get("as_name") or details.get("isp")
    asn = details.get("asn") or details.get("as_number")
    if not any((country, city, org, asn)):
        return None
    return {
        "country": country,
        "cc": cc,
        "city": city,
        "region": region,
        "org": org,
        "asn": asn,
    }


def _geo_richness(g: dict) -> int:
    """Count how many fields a geo candidate fills — used to keep the
    most detailed geolocation when several sources disagree."""
    return sum(
        1 for v in (g["city"], g["region"], g["country"], g["org"], g["asn"]) if v
    )


def _host_from_details(details: dict) -> str | None:
    """Pull a hostname / domain for the IP out of one evidence row's
    details: Shodan InternetDB carries reverse-DNS ``hostnames`` (keyless,
    on by default), AbuseIPDB carries a registered ``domain``. ``None``
    when the row names no host."""
    hostnames = details.get("hostnames")
    if isinstance(hostnames, list):
        for h in hostnames:
            if isinstance(h, str) and h:
                return h
    dom = details.get("domain")
    if isinstance(dom, str) and dom:
        return dom
    return None


def _attach_ip_enrichment(session: Session, rows: list[dict]) -> None:
    """Populate each flow row from the cached enrichment evidence for its
    destination IP:

    - ``geo``:      the richest geolocation (country / city / region /
      org / ASN) across any source — ipwho.is primarily, with AbuseIPDB /
      Feodo as fallbacks.
    - ``hostname``: a reverse-DNS hostname / domain for the IP, if any
      source resolved one (Shodan ``hostnames``, AbuseIPDB ``domain``).

    Both default to ``None``. No-op if the enrichment cache table doesn't
    exist or there are no rows.
    """
    for r in rows:
        r["geo"] = None
        r["hostname"] = None
    if not rows or "enrichment_evidence" not in _existing_tables(session):
        return
    ips = [r["dst_ip"] for r in rows if r.get("dst_ip")]
    if not ips:
        return
    # Register the enrichment ORM model against the dashboard's Base
    # (idempotent — no-op if the monitor's startup already did it) so we
    # can query the cache through the ORM rather than raw SQL.
    from avai.enrichers import IndicatorType
    from avai.enrichers.cache import register_schema

    model = register_schema(Base)
    stmt = select(
        model.indicator_value,
        model.details_json,
    ).where(
        model.indicator_type.in_([str(IndicatorType.IPV4), str(IndicatorType.IPV6)]),
        model.indicator_value.in_(ips),
    )
    geo_by_ip: dict[str, dict] = {}
    host_by_ip: dict[str, set] = {}
    for ip, details_json in session.execute(stmt).all():
        try:
            details = json.loads(details_json) if details_json else {}
        except (TypeError, ValueError):
            details = {}
        geo = _geo_from_details(details)
        if geo is not None:
            best = geo_by_ip.get(ip)
            if best is None or _geo_richness(geo) > _geo_richness(best):
                geo_by_ip[ip] = geo
        host = _host_from_details(details)
        if host:
            host_by_ip.setdefault(ip, set()).add(host)
    for r in rows:
        r["geo"] = geo_by_ip.get(r["dst_ip"])
        hosts = host_by_ip.get(r["dst_ip"])
        # Deterministic pick when several sources name different hosts.
        r["hostname"] = sorted(hosts)[0] if hosts else None


def _collector_rows_with_verdict(
    session: Session,
    run_id: str,
    model,
    collector: str,
    fields: tuple[str, ...],
    limit: int = 500,
) -> list[dict]:
    """Generic: every ``collector`` row for ``run_id``, each annotated
    with its LLM verdict (LEFT JOIN Judgement on content_hash). ``fields``
    are the model attributes to return; a missing newer column degrades
    to NULL (older DB) and a missing table returns ``[]``. Worst verdict
    first. Shared by the DNS and persistence dashboard sections so they
    don't each re-implement the join."""
    if model.__tablename__ not in _existing_tables(session):
        return []
    present = _existing_columns(session, model.__tablename__)
    selected = [
        getattr(model, f) if f in present else literal(None).label(f) for f in fields
    ]
    stmt = (
        select(
            *selected,
            Judgement.verdict,
            Judgement.confidence,
            Judgement.reasoning,
        )
        .outerjoin(
            Judgement,
            and_(
                Judgement.content_hash == model.content_hash,
                Judgement.collector == collector,
            ),
        )
        .where(model.run_id == run_id)
        .limit(limit)
    )
    out: list[dict] = []
    n = len(fields)
    for row in session.execute(stmt).all():
        d = {f: row[i] for i, f in enumerate(fields)}
        d["verdict"] = row[n]
        d["confidence"] = row[n + 1]
        d["reasoning"] = row[n + 2]
        out.append(d)
    out.sort(key=lambda r: _FLOW_SEV.get(r["verdict"], 4))
    return out


def _dns_resolution_level(server_ip, qtype) -> str:
    """Classify *how/where* a name resolved, from the resolver it was
    asked and the transport:

    - ``DoH (encrypted)`` — answered over DNS-over-HTTPS (we can't see the
      name, only that the host used an encrypted resolver).
    - ``local resolver`` — asked a private/LAN address (the router or a
      local stub like 127.0.0.1 / mDNSResponder forwarder).
    - ``external DNS`` — asked a public resolver directly (8.8.8.8, the
      ISP, …), bypassing any local one.

    Names served from ``/etc/hosts`` never hit the wire, so they don't
    appear here — they're shown in the persistence & tampering section.
    """
    if qtype == "DoH":
        return "DoH (encrypted)"
    if not server_ip:
        return "unknown"
    try:
        ip = ipaddress.ip_address(server_ip)
    except ValueError:
        return "unknown"
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return "local resolver"
    return "external DNS"


def dns_queries(session: Session, run_id: str, limit: int = 1000):
    """DNS questions seen this run (+ detected DoH endpoints), each with
    its LLM verdict and the resolution level (where/how it resolved).
    Returns ``{"summary": {...}, "rows": [...]}`` sorted worst-verdict
    then most-queried."""
    rows = _collector_rows_with_verdict(
        session,
        run_id,
        DnsQueryRow,
        "dns_queries",
        ("qname", "qtype", "server_ip", "process", "count"),
        limit=limit,
    )
    for r in rows:
        r["level"] = _dns_resolution_level(r["server_ip"], r["qtype"])
    rows.sort(key=lambda r: (_FLOW_SEV.get(r["verdict"], 4), -(r["count"] or 0)))
    summary = {
        "domains": len({r["qname"] for r in rows}),
        "queries": sum(r["count"] or 0 for r in rows),
        "doh": sum(1 for r in rows if r["qtype"] == "DoH"),
        "malicious": sum(1 for r in rows if r["verdict"] == "malicious"),
        "suspicious": sum(1 for r in rows if r["verdict"] == "suspicious"),
    }
    return {"summary": summary, "rows": rows}


def persistence_tampering(session: Session, run_id: str, limit: int = 500):
    """The persistence & tampering posture for ``run_id``: SSH authorized
    keys, /etc/hosts mappings, and privilege config — each list annotated
    with LLM verdicts, plus per-table counts for the section header."""
    ssh = _collector_rows_with_verdict(
        session,
        run_id,
        SshAuthorizedKeyRow,
        "ssh_authorized_keys",
        ("owner", "key_type", "fingerprint", "comment", "options", "path"),
        limit,
    )
    hosts = _collector_rows_with_verdict(
        session,
        run_id,
        HostsFileRow,
        "hosts_file",
        ("ip", "hostnames", "source_path"),
        limit,
    )
    priv = _collector_rows_with_verdict(
        session,
        run_id,
        PrivilegeConfigRow,
        "privilege_config",
        ("kind", "subject", "detail", "source_path"),
        limit,
    )

    def _counts(rs: list[dict]) -> dict:
        return {
            "total": len(rs),
            "malicious": sum(1 for r in rs if r["verdict"] == "malicious"),
            "suspicious": sum(1 for r in rs if r["verdict"] == "suspicious"),
        }

    return {
        "ssh_keys": ssh,
        "hosts": hosts,
        "privilege": priv,
        "counts": {
            "ssh_keys": _counts(ssh),
            "hosts": _counts(hosts),
            "privilege": _counts(priv),
        },
        "any": bool(ssh or hosts or priv),
    }


def system_integrity(session: Session, run_id: str):
    """Return the latest system-integrity posture as a platform-tagged
    dict the template can render directly.

    macOS and Linux write to the same table but different places:
    the macOS collector fills the named columns (filevault_active, …);
    the Linux collector puts everything in ``raw_json`` (selinux,
    apparmor, ufw, …). We detect which one produced the row and emit
    the matching labels — otherwise a Linux row (or vice-versa) renders
    under the wrong OS's labels and an unset column reads as a scary,
    false "OFF" (e.g. "FileVault OFF" for data collected in a Linux VM).
    """
    row = session.execute(
        select(SystemIntegrityRow).where(SystemIntegrityRow.run_id == run_id).limit(1)
    ).scalar_one_or_none()
    if row is None:
        return None

    try:
        raw = json.loads(row.raw_json) if row.raw_json else {}
    except (json.JSONDecodeError, TypeError):
        raw = {}

    linux_keys = {
        "selinux",
        "apparmor",
        "ufw_active",
        "firewalld_active",
        "sshd_active",
        "vnc_active",
        "luks_mappings",
    }
    if linux_keys & set(raw):
        apparmor = raw.get("apparmor")
        apparmor_on = (
            apparmor.get("enabled") if isinstance(apparmor, dict) else apparmor
        )
        return {
            "platform": "Linux",
            "rows": [
                ("SELinux", raw.get("selinux")),
                ("AppArmor", apparmor_on),
                ("Firewall (ufw)", raw.get("ufw_active")),
                ("Firewall (firewalld)", raw.get("firewalld_active")),
                ("SSH (sshd)", raw.get("sshd_active")),
                ("VNC", raw.get("vnc_active")),
                ("Disk encryption (LUKS)", bool(raw.get("luks_mappings"))),
            ],
        }
    return {
        "platform": "macOS",
        "rows": [
            ("FileVault", row.filevault_active),
            ("Firewall", row.firewall_global_state),
            ("Firewall stealth", row.firewall_stealth),
            ("Gatekeeper", row.gatekeeper_assessments_enabled),
            ("SSH (sshd)", row.remote_login_enabled),
            ("Screen Sharing", row.screen_sharing_enabled),
            ("Remote Mgmt (ARD)", row.remote_management_enabled),
        ],
    }


def new_alerts(session: Session, since: str | None, limit: int = 50) -> list[dict]:
    """Return malicious / suspicious judgements created after ``since``,
    newest first. Drives the browser-side toast + beep alert. Each
    item carries enough context to render a self-contained card
    (verdict, collector, category, reasoning, remediation, artifact)
    without requiring a follow-up request.

    Note: this returns *judgements*, not snapshot rows. A judgement is
    created exactly once per unique content_hash. So the same artifact
    won't alert twice across runs (the dedupe is intrinsic).
    """
    stmt = select(Judgement).where(Judgement.verdict.in_(("malicious", "suspicious")))
    if since:
        stmt = stmt.where(Judgement.created_at > since)
    stmt = stmt.order_by(desc(Judgement.created_at)).limit(limit)

    items = []
    for j in session.execute(stmt).scalars():
        _, artifact = _row_and_artifact(session, j)
        items.append(
            {
                "content_hash": j.content_hash,
                "collector": j.collector,
                "verdict": j.verdict,
                "category": j.category or "none",
                "confidence": j.confidence or 0.0,
                "reasoning": j.reasoning or "",
                "remediation": j.remediation or "",
                "created_at": j.created_at,
                "artifact": artifact,
            }
        )
    return items


def verdict_timeseries(session: Session, hours: int = 12) -> dict:
    """Return verdict counts grouped per-hour bucket over the last N hours.
    Returns: {"labels": [...iso hours...], "datasets": {verdict: [counts...]}}
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(
        timespec="seconds"
    )
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
            judged_this_run=(judged_since(s, latest.started_at) if latest else 0),
        )


@app.route("/fragments/sysint")
def fragment_sysint():
    with _session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_sysint.html",
            sysint=(system_integrity(s, latest.run_id) if latest else None),
        )


@app.route("/fragments/network-flows")
def fragment_network_flows():
    with _session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_network_flows.html",
            flows=(network_flows(s, latest.run_id) if latest else []),
        )


@app.route("/fragments/dns-queries")
def fragment_dns_queries():
    with _session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_dns_queries.html",
            dns=(dns_queries(s, latest.run_id) if latest else None),
        )


@app.route("/fragments/persistence")
def fragment_persistence():
    with _session() as s:
        latest = latest_run(s)
        return render_template(
            "partials/_persistence.html",
            data=(persistence_tampering(s, latest.run_id) if latest else None),
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


# ============================================================================
# Entry point
# ============================================================================


def main() -> int:
    parser = argparse.ArgumentParser(
        description="avai — read-only Flask + HTMX dashboard for the host monitor DB"
    )
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    app.config["DB_PATH"] = args.db
    _ensure_db_exists(args.db)
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


def _ensure_db_exists(db_path: str) -> None:
    """Create an empty schema if the DB file doesn't exist yet.

    The dashboard opens the database read-only with ``immutable=1``,
    which SQLite *refuses* to apply to a non-existent file (the
    immutable flag promises the file won't change — there's no file
    to promise about). Without this, a dashboard launched before the
    monitor has run produces 500s on every query.

    Creating the schema also makes empty-state rendering work: every
    table exists, every query returns zero rows, every panel renders
    empty rather than erroring.
    """
    db_file = Path(db_path)
    if db_file.exists() and db_file.stat().st_size > 0:
        return
    db_file.parent.mkdir(parents=True, exist_ok=True)
    # Register the enrichment model on Base.metadata before create_all,
    # so a dashboard-only deployment (no monitor co-located) still gets
    # the enrichment_evidence table — otherwise any dashboard query
    # against it 500s.
    from avai.enrichers.cache import register_schema

    register_schema(Base)
    write_engine = create_engine(f"sqlite:///{db_path}")
    try:
        Base.metadata.create_all(write_engine)
    finally:
        write_engine.dispose()


if __name__ == "__main__":
    sys.exit(main())
