"""Read-only DB query layer — no Flask app, uses current_app for config."""
from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from flask import current_app, request
from sqlalchemy import and_, asc, case, create_engine, desc, func, literal, or_, select, text
from sqlalchemy.orm import Session
from avai.host_monitor import AuthEventRow, Base, BluetoothDeviceRow, BrowserExtensionRow, CollectionRun, CollectorErrorRow, DnsQueryRow, FileIntegrityRow, HostsFileRow, IncidentNarrativeRow, InstalledAppRow, Judgement, KernelExtensionRow, LaunchItemRow, ListeningPortRow, MdmProfileRow, MountRow, NetworkConnectionRow, NetworkFlowRow, NetworkInterfaceRow, PrivilegeConfigRow, ProcessExecRow, ProcessRow, QuarantineEventRow, RiskScoreRow, SetuidFileRow, SshAuthorizedKeyRow, SystemExtensionRow, SystemIntegrityRow, UsbDeviceRow, WifiStateRow


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


DEFAULT_DB_PATH = Path.home() / ".avai" / "avai.db"


_HIDDEN_SOURCE_FIELDS = {"id", "run_id"}


_engine_cache: dict[str, object] = {}


_engine_cache_lock = threading.Lock()


def _engine():
    """Return a process-wide, thread-safe read-only engine for the
    configured DB, built once per path and reused thereafter.

    This used to build a *new* engine (and connection pool) on every
    request and never dispose it. Under the dashboard's ~dozen HTMX
    fragments — which all poll concurrently — that leaked SQLite
    connections/file handles and saturated the WSGI worker threads
    (waitress "task queue depth" warnings). Caching one engine per path
    reuses a pooled set of connections instead, so requests return fast
    and threads free up promptly.

    We open read-only (``mode=ro``) and deliberately do NOT pass
    ``immutable=1``: ``immutable=1`` tells SQLite to ignore the ``-wal``
    file, so on a live DB the monitor is writing (especially before the
    first WAL checkpoint) the reader would see an empty/incomplete
    database and every query would 500 with "no such table". ``mode=ro``
    reads the WAL correctly, so the dashboard sees live data immediately;
    a fresh read transaction per query still picks up newly committed
    rows. ``check_same_thread=False`` is required because waitress hands
    pooled connections to different worker threads.
    """
    db_path = current_app.config["DB_PATH"]
    eng = _engine_cache.get(db_path)
    if eng is None:
        with _engine_cache_lock:
            eng = _engine_cache.get(db_path)
            if eng is None:
                eng = create_engine(
                    f"sqlite:///file:{db_path}?mode=ro&uri=true",
                    connect_args={"check_same_thread": False},
                )
                if _QUERY_LOG_PATH:
                    from sqlalchemy import event

                    event.listen(eng, "before_cursor_execute", _log_query)
                _engine_cache[db_path] = eng
    return eng


_QUERY_LOG_PATH = os.environ.get("AVAI_QUERY_LOG")


_query_log_lock = threading.Lock()


def _log_query(conn, cursor, statement, parameters, context, executemany):
    """SQLAlchemy before_cursor_execute hook → append one line per query."""
    try:
        from flask import has_request_context

        route = request.path if has_request_context() else "-"
    except Exception:
        route = "-"
    sql = " ".join(str(statement).split())
    params = str(parameters)
    if len(params) > 300:
        params = params[:300] + "…"
    line = (
        f"{datetime.now(timezone.utc).isoformat(timespec='seconds')}\t"
        f"{route}\t{sql}\t{params}\n"
    )
    with _query_log_lock:
        try:
            with open(_QUERY_LOG_PATH, "a") as fh:
                fh.write(line)
        except OSError:
            pass


def _session() -> Session:
    return Session(_engine())


_SCHEMA_TTL = 30.0


_tables_cache: dict[str, tuple[float, set]] = {}


_columns_cache: dict[tuple[str, str], tuple[float, set]] = {}


def _cache_key(session: Session) -> str:
    return str(session.get_bind().url)


def _existing_tables(session: Session) -> set[str]:
    """Tables actually present in the DB. The dashboard may read a
    database written by an *older* monitor that predates a collector
    (e.g. network_flows), so querying a not-yet-created table would 500.
    Callers check membership here and degrade gracefully instead. Cached."""
    key = _cache_key(session)
    hit = _tables_cache.get(key)
    if hit is not None and time.monotonic() - hit[0] < _SCHEMA_TTL:
        return hit[1]
    tables = set(
        session.execute(
            text("SELECT name FROM sqlite_master WHERE type='table'")
        ).scalars()
    )
    _tables_cache[key] = (time.monotonic(), tables)
    return tables


def _existing_columns(session: Session, table: str) -> set[str]:
    """Column names present on ``table``. The DB may have been written by
    an older monitor missing a newly-added column (e.g. network_flows.
    iface); selecting it would 500. Callers substitute a NULL literal
    for absent columns instead. Cached."""
    key = (_cache_key(session), table)
    hit = _columns_cache.get(key)
    if hit is not None and time.monotonic() - hit[0] < _SCHEMA_TTL:
        return hit[1]
    rows = session.execute(text(f"PRAGMA table_info({table})")).all()
    cols = {r[1] for r in rows}  # row[1] is the column name
    _columns_cache[key] = (time.monotonic(), cols)
    return cols


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


def latest_narrative(session: Session):
    """The most recent incident digest, or None. Guarded for DBs written by
    an older monitor that predates the ``incident_narratives`` table."""
    if "incident_narratives" not in _existing_tables(session):
        return None
    return session.execute(
        select(IncidentNarrativeRow)
        .order_by(desc(IncidentNarrativeRow.created_at))
        .limit(1)
    ).scalar_one_or_none()


def latest_risk(session: Session):
    """Most recent host posture score, or None. Guarded for older DBs that
    predate the ``risk_scores`` table."""
    if "risk_scores" not in _existing_tables(session):
        return None
    return session.execute(
        select(RiskScoreRow).order_by(desc(RiskScoreRow.created_at)).limit(1)
    ).scalar_one_or_none()


def risk_trend(session: Session, limit: int = 30) -> list[int]:
    """Recent scores oldest→newest for the sparkline. [] if unavailable."""
    if "risk_scores" not in _existing_tables(session):
        return []
    rows = (
        session.execute(
            select(RiskScoreRow.score)
            .order_by(desc(RiskScoreRow.created_at))
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return list(reversed(rows))


_VULN_SOURCES = ("osv", "nvd", "cisa_kev", "github_advisory", "endoflife")


def vulnerabilities(session: Session) -> list[dict]:
    """Aggregate the CVE / EOL evidence the enrichment chain already
    collected into a prioritised 'patch me' list (KEV → has-CVE → EOL).
    Reads the enrichment_evidence cache; [] if it isn't present."""
    if "enrichment_evidence" not in _existing_tables(session):
        return []
    from avai.enrichers.cache import register_schema

    model = register_schema(Base)
    rows = session.execute(
        select(
            model.source,
            model.indicator_type,
            model.indicator_value,
            model.verdict_hint,
            model.confidence,
            model.summary,
            model.details_json,
        ).where(model.source.in_(_VULN_SOURCES))
    ).all()

    parsed = []
    cve_detail: dict[str, dict] = {}  # CVE id -> {kev, cvss, severity}
    for src, itype, ival, hint, conf, summary, dj in rows:
        try:
            details = json.loads(dj) if dj else {}
        except (TypeError, ValueError):
            details = {}
        parsed.append((src, itype, ival, hint, summary, details))
        if itype == "cve":
            # forward-chained CVE rows carry the severity/exploited detail
            d = cve_detail.setdefault(
                ival.upper(), {"kev": False, "cvss": None, "severity": None}
            )
            if src == "cisa_kev":
                d["kev"] = True
            score = (details.get("cvss31") or {}).get("baseScore")
            if score is None:
                score = (details.get("cvss") or {}).get("score")
            try:
                score = float(score) if score is not None else None
            except (TypeError, ValueError):
                score = None
            if score is not None and (d["cvss"] is None or score > d["cvss"]):
                d["cvss"] = score
            sev = (details.get("cvss31") or {}).get("baseSeverity") or details.get(
                "severity"
            )
            if sev and not d["severity"]:
                d["severity"] = str(sev).lower()

    items: list[dict] = []
    for src, itype, ival, hint, summary, details in parsed:
        eol = src == "endoflife" and hint != "benign"
        ids = details.get("vuln_ids") or []
        # CVE-typed rows feed cve_detail only — they're shown attached to
        # their parent package, not as standalone rows.
        if not ids and not eol:
            continue
        cves = [
            {
                "id": cid,
                **cve_detail.get(
                    str(cid).upper(), {"kev": False, "cvss": None, "severity": None}
                ),
            }
            for cid in ids
        ]
        kev = any(c["kev"] for c in cves)
        cvss = max((c["cvss"] for c in cves if c["cvss"] is not None), default=None)
        items.append(
            {
                "software": ival,
                "source": src,
                "cves": cves,
                "kev": kev,
                "cvss": cvss,
                "eol": eol,
                "summary": summary or "",
            }
        )
    # prioritise: actively-exploited (KEV) → highest CVSS → has-CVE → EOL
    items.sort(
        key=lambda i: (
            not i["kev"],
            -(i["cvss"] or 0.0),
            not i["cves"],
            not i["eol"],
            i["software"],
        )
    )
    return items


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


def cost_since(session: Session, since: str) -> float:
    """Total estimated LLM cost (USD) of judgments produced since ``since``."""
    return float(
        session.execute(
            select(func.coalesce(func.sum(Judgement.cost_usd), 0.0)).where(
                Judgement.created_at >= since
            )
        ).scalar()
        or 0.0
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
    # Clamp to the last page, mirroring _paginate. Without the upper bound a
    # huge ?page= produces an OFFSET past SQLite's 64-bit INTEGER range and
    # raises OverflowError → HTTP 500.
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    stmt = stmt.offset((page - 1) * per_page).limit(per_page)

    raw = session.execute(stmt).scalars().all()

    # Batch the artifact lookup: one query per collector (content_hash IN …)
    # instead of one per finding. Keep the latest row per content_hash.
    hashes_by_collector: dict[str, set[str]] = {}
    for j in raw:
        hashes_by_collector.setdefault(j.collector, set()).add(j.content_hash)
    artifacts: dict[tuple, tuple] = {}
    for collector, hashes in hashes_by_collector.items():
        model = COLLECTOR_MODELS.get(collector)
        if model is None:
            continue
        seen: set[str] = set()
        for row_obj in session.execute(
            select(model)
            .where(model.content_hash.in_(hashes))
            .order_by(model.collected_at.desc())
        ).scalars():
            if row_obj.content_hash in seen:  # desc order → first is latest
                continue
            seen.add(row_obj.content_hash)
            full = {
                col.name: getattr(row_obj, col.name)
                for col in model.__table__.columns
                if col.name not in _HIDDEN_SOURCE_FIELDS
            }
            fields = DISPLAY_FIELDS.get(collector, ())
            artifacts[(collector, row_obj.content_hash)] = (
                full,
                " · ".join(
                    str(full[f]) for f in fields if full.get(f) not in (None, "")
                ),
            )

    items = []
    for j in raw:
        source_row, artifact = artifacts.get((j.collector, j.content_hash), ({}, ""))
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
                "novel": bool(getattr(j, "novel", 0)),
                "context": _parse_json_obj(getattr(j, "context_json", None)),
                "cost_usd": getattr(j, "cost_usd", None) or 0.0,
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


_STREAMING_COLLECTORS = {"auth_events", "process_exec_events"}


def row_counts(
    session: Session,
    latest_run_id: str,
    latest_started: str,
    prev_run_id: str | None = None,
    prev_started: str | None = None,
) -> list[dict]:
    """Per-collector row counts for the latest run, with a change signal vs
    the previous run.

    Snapshot collectors are counted by ``run_id`` (already indexed) instead
    of a ``collected_at`` range — turning per-table full scans into index
    counts. Streaming collectors use an ``event_timestamp`` window (also
    indexed). ``delta``/``is_new`` describe the change vs the previous run.
    """
    out = []
    present = _existing_tables(session)
    for name, model in COLLECTOR_MODELS.items():
        if model.__tablename__ not in present:
            continue
        if name in _STREAMING_COLLECTORS:
            # streaming tables accumulate across sessions → time window
            ts = model.event_timestamp
            cur = session.execute(
                select(func.count()).select_from(model).where(ts >= latest_started)
            ).scalar()
            prev = (
                session.execute(
                    select(func.count())
                    .select_from(model)
                    .where(ts >= prev_started, ts < latest_started)
                ).scalar()
                if prev_started is not None
                else None
            )
        else:
            # snapshot tables are keyed by run_id (indexed)
            cur = session.execute(
                select(func.count())
                .select_from(model)
                .where(model.run_id == latest_run_id)
            ).scalar()
            prev = (
                session.execute(
                    select(func.count())
                    .select_from(model)
                    .where(model.run_id == prev_run_id)
                ).scalar()
                if prev_run_id is not None
                else None
            )
        cur = cur or 0
        delta = (cur - (prev or 0)) if prev is not None else None
        is_new = prev == 0 and cur > 0 if prev is not None else False
        out.append({"name": name, "rows": cur, "delta": delta, "is_new": is_new})
    out.sort(key=lambda x: x["rows"], reverse=True)
    return out


def collector_errors(session: Session, run_id: str) -> list[CollectorErrorRow]:
    return list(
        session.execute(
            select(CollectorErrorRow).where(CollectorErrorRow.run_id == run_id)
        ).scalars()
    )


_FLOW_SEV = {"malicious": 0, "suspicious": 1, "unknown": 2, "benign": 3, None: 4}


def _paginate(rows: list, page: int, per_page: int) -> tuple[list, int, int]:
    """Slice *rows* for the requested page. Returns (page_rows, total, total_pages)."""
    total = len(rows)
    per_page = max(1, min(per_page, 200))
    page = max(1, page)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    return rows[(page - 1) * per_page : page * per_page], total, total_pages


def network_flows(
    session: Session,
    run_id: str,
    limit: int = 1000,
    verdict: str = "",
    q: str = "",
    page: int = 1,
    per_page: int = DEFAULT_PER_PAGE,
):
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

    # Apply filters
    if verdict:
        rows = [r for r in rows if r.get("verdict") == verdict]
    if q:
        ql = q.lower()
        rows = [
            r
            for r in rows
            if ql in (r.get("dst_ip") or "").lower()
            or ql in (r.get("hostname") or "").lower()
            or ql in (r.get("process") or "").lower()
        ]

    summary = {
        "destinations": len(rows),
        "flows": sum(r["flows"] for r in rows),
        "packets": sum(r["packets"] for r in rows),
        "bytes": sum(r["bytes"] for r in rows),
        "malicious": sum(1 for r in rows if r["verdict"] == "malicious"),
        "suspicious": sum(1 for r in rows if r["verdict"] == "suspicious"),
    }

    page_rows, total, total_pages = _paginate(rows, page, per_page)
    return {
        "summary": summary,
        "rows": page_rows,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "q": q,
        "verdict": verdict,
    }


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


_PROTO_BY_SOCK = {"SOCK_STREAM": "TCP", "SOCK_DGRAM": "UDP"}


_FAMILY_LABEL = {"AF_INET": "IPv4", "AF_INET6": "IPv6"}


def _addr_scope(ip) -> str:
    """Classify a listening bind address — the dominant threat signal:
    ``all`` (0.0.0.0 / ::, reachable from any interface), ``loopback``
    (127.0.0.0/8 / ::1, local-only), ``specific`` (a routable/LAN IP), or
    ``unknown``."""
    if not ip:
        return "unknown"
    if ip in ("0.0.0.0", "::"):
        return "all"
    try:
        if ipaddress.ip_address(ip).is_loopback:
            return "loopback"
    except ValueError:
        return "unknown"
    return "specific"


_SCOPE_SEV = {"all": 0, "specific": 1, "unknown": 2, "loopback": 3}


def _cmdline_str(raw) -> str | None:
    """ProcessRow.cmdline_json is a JSON-encoded argv list; render it as a
    single command string, or None when absent/unparseable."""
    if not raw:
        return None
    try:
        parts = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if isinstance(parts, list) and parts:
        return " ".join(str(x) for x in parts)
    return None


def listening_ports(
    session: Session,
    run_id: str,
    limit: int = 1000,
    verdict: str = "",
    scope_filter: str = "",
    q: str = "",
    page: int = 1,
    per_page: int = DEFAULT_PER_PAGE,
):
    """Listening sockets for ``run_id`` as a glanceable table: one row per
    (port, pid) socket, annotated with its LLM verdict (LEFT JOIN
    Judgement, same as :func:`network_flows`) and enriched with
    owning-process detail (user, exe, cmdline, cpu/mem, ppid) from the
    ``processes`` snapshot plus a count of established connections to that
    local port from ``network_connections``.

    Wildcard binds (0.0.0.0 + :: on the same port/pid) merge into one row
    carrying the worst bind scope, so the table reads as "what is this
    process exposing, and to whom". Worst-verdict-first, then by port.
    Returns ``{"summary": {...}, "rows": [...]}``; degrades to empty when
    the table predates this collector."""
    empty = {
        "summary": {"ports": 0, "exposed": 0, "malicious": 0, "suspicious": 0},
        "rows": [],
    }
    if "listening_ports" not in _existing_tables(session):
        return empty

    # Owning-process detail, keyed by pid, from the same run's snapshot.
    proc_by_pid: dict[int, dict] = {}
    if "processes" in _existing_tables(session):
        for p in session.execute(
            select(
                ProcessRow.pid,
                ProcessRow.ppid,
                ProcessRow.exe,
                ProcessRow.cmdline_json,
                ProcessRow.username,
                ProcessRow.uid,
                ProcessRow.status,
                ProcessRow.cpu_percent,
                ProcessRow.memory_rss,
                ProcessRow.num_fds,
                ProcessRow.num_threads,
            ).where(ProcessRow.run_id == run_id)
        ).all():
            if p.pid is None:
                continue
            proc_by_pid[p.pid] = {
                "ppid": p.ppid,
                "exe": p.exe,
                "cmdline": _cmdline_str(p.cmdline_json),
                "username": p.username,
                "uid": p.uid,
                "status": p.status,
                "cpu_percent": p.cpu_percent,
                "memory_rss": p.memory_rss,
                "num_fds": p.num_fds,
                "num_threads": p.num_threads,
            }

    # Established connections terminating on each local port — "is anyone
    # actually talking to this listener right now".
    conn_count: dict[int, int] = {}
    if "network_connections" in _existing_tables(session):
        for port, n in session.execute(
            select(NetworkConnectionRow.laddr_port, func.count())
            .where(
                NetworkConnectionRow.run_id == run_id,
                NetworkConnectionRow.status == "ESTABLISHED",
            )
            .group_by(NetworkConnectionRow.laddr_port)
        ).all():
            if port is not None:
                conn_count[port] = n

    stmt = (
        select(
            ListeningPortRow.pid,
            ListeningPortRow.process_name,
            ListeningPortRow.family,
            ListeningPortRow.type,
            ListeningPortRow.laddr_ip,
            ListeningPortRow.laddr_port,
            Judgement.verdict,
            Judgement.confidence,
            Judgement.reasoning,
        )
        .outerjoin(
            Judgement,
            and_(
                Judgement.content_hash == ListeningPortRow.content_hash,
                Judgement.collector == "listening_ports",
            ),
        )
        .where(ListeningPortRow.run_id == run_id)
        .limit(limit)
    )

    groups: dict[tuple, dict] = {}
    for (
        pid,
        process_name,
        family,
        type_,
        laddr_ip,
        laddr_port,
        verdict,
        conf,
        reason,
    ) in session.execute(stmt).all():
        key = (laddr_port, pid)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "port": laddr_port,
                "pid": pid,
                "process": process_name,
                "_addrs": set(),
                "_protos": set(),
                "_families": set(),
                "verdict": None,
                "confidence": None,
                "reasoning": "",
            }
        if laddr_ip:
            g["_addrs"].add(laddr_ip)
        if type_:
            g["_protos"].add(_PROTO_BY_SOCK.get(type_, type_))
        if family:
            g["_families"].add(_FAMILY_LABEL.get(family, family))
        if _FLOW_SEV.get(verdict, 4) < _FLOW_SEV.get(g["verdict"], 4):
            g["verdict"] = verdict
            g["confidence"] = conf
            g["reasoning"] = reason or ""

    rows = []
    for g in groups.values():
        scopes = {_addr_scope(a) for a in g["_addrs"]} or {"unknown"}
        scope = min(scopes, key=lambda s: _SCOPE_SEV.get(s, 2))
        rows.append(
            {
                "port": g["port"],
                "pid": g["pid"],
                "process": g["process"] or "—",
                "addrs": sorted(g["_addrs"]),
                "scope": scope,
                "exposed": scope in ("all", "specific"),
                "proto": sorted(g["_protos"]),
                "family": sorted(g["_families"]),
                "conns": conn_count.get(g["port"], 0),
                "proc": proc_by_pid.get(g["pid"]),
                "verdict": g["verdict"],
                "confidence": g["confidence"],
                "reasoning": g["reasoning"],
            }
        )

    rows.sort(key=lambda r: (_FLOW_SEV.get(r["verdict"], 4), r["port"] or 0))

    # Apply filters
    if verdict:
        rows = [r for r in rows if r.get("verdict") == verdict]
    if scope_filter:
        rows = [r for r in rows if r.get("scope") == scope_filter]
    if q:
        ql = q.lower()
        rows = [
            r
            for r in rows
            if ql in (r.get("process") or "").lower() or ql in str(r.get("port") or "")
        ]

    summary = {
        "ports": len(rows),
        "exposed": sum(1 for r in rows if r["exposed"]),
        "malicious": sum(1 for r in rows if r["verdict"] == "malicious"),
        "suspicious": sum(1 for r in rows if r["verdict"] == "suspicious"),
    }

    page_rows, total, total_pages = _paginate(rows, page, per_page)
    return {
        "summary": summary,
        "rows": page_rows,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "q": q,
        "verdict": verdict,
        "scope_filter": scope_filter,
    }


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


def dns_queries(
    session: Session,
    run_id: str,
    limit: int = 1000,
    verdict: str = "",
    level: str = "",
    q: str = "",
    page: int = 1,
    per_page: int = DEFAULT_PER_PAGE,
):
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

    # Apply filters
    if verdict:
        rows = [r for r in rows if r.get("verdict") == verdict]
    if level:
        rows = [r for r in rows if r.get("level") == level]
    if q:
        ql = q.lower()
        rows = [
            r
            for r in rows
            if ql in (r.get("qname") or "").lower()
            or ql in (r.get("process") or "").lower()
        ]

    summary = {
        "domains": len({r["qname"] for r in rows}),
        "queries": sum(r["count"] or 0 for r in rows),
        "doh": sum(1 for r in rows if r["qtype"] == "DoH"),
        "malicious": sum(1 for r in rows if r["verdict"] == "malicious"),
        "suspicious": sum(1 for r in rows if r["verdict"] == "suspicious"),
    }

    page_rows, total, total_pages = _paginate(rows, page, per_page)
    return {
        "summary": summary,
        "rows": page_rows,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "q": q,
        "verdict": verdict,
        "level": level,
    }


def persistence_tampering(
    session: Session,
    run_id: str,
    limit: int = 500,
    verdict: str = "",
    q: str = "",
    ssh_page: int = 1,
    hosts_page: int = 1,
    priv_page: int = 1,
    per_page: int = DEFAULT_PER_PAGE,
):
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

    def _filter_rows(rs, fields):
        if verdict:
            rs = [r for r in rs if r.get("verdict") == verdict]
        if q:
            ql = q.lower()
            rs = [
                r for r in rs if any(ql in str(r.get(f) or "").lower() for f in fields)
            ]
        return rs

    ssh = _filter_rows(ssh, ("owner", "key_type", "fingerprint", "comment"))
    hosts = _filter_rows(hosts, ("ip", "hostnames"))
    priv = _filter_rows(priv, ("kind", "subject", "detail"))

    ssh_rows, ssh_total, ssh_pages = _paginate(ssh, ssh_page, per_page)
    hosts_rows, hosts_total, hosts_pages = _paginate(hosts, hosts_page, per_page)
    priv_rows, priv_total, priv_pages = _paginate(priv, priv_page, per_page)

    return {
        "ssh_keys": ssh_rows,
        "hosts": hosts_rows,
        "privilege": priv_rows,
        "counts": {
            "ssh_keys": _counts(ssh),
            "hosts": _counts(hosts),
            "privilege": _counts(priv),
        },
        "pagination": {
            "ssh": {"page": ssh_page, "total": ssh_total, "total_pages": ssh_pages},
            "hosts": {
                "page": hosts_page,
                "total": hosts_total,
                "total_pages": hosts_pages,
            },
            "priv": {"page": priv_page, "total": priv_total, "total_pages": priv_pages},
        },
        "per_page": per_page,
        "verdict": verdict,
        "q": q,
        "any": bool(ssh or hosts or priv),
    }


_AUTH_SUBSYSTEM_LABELS = {
    "com.apple.securityd": "securityd",
    "com.apple.TCC": "TCC",
    "com.apple.opendirectoryd": "opendirectoryd",
    "com.apple.syspolicy": "syspolicy",
    "com.apple.loginwindow.logging": "loginwindow",
    "com.apple.launchservices": "launchservices",
    "com.apple.Authorization": "Authorization",
    "com.apple.xpc": "xpc",
    "com.apple.CFPasteboard": "CFPasteboard",
    "com.apple.BezelServices": "BezelServices",
    "com.apple.ManagedClient": "ManagedClient",
}


AUTH_SUBSYSTEM_OPTIONS = [
    ("all subsystems", ""),
    ("TCC (privacy access)", "com.apple.TCC"),
    ("securityd", "com.apple.securityd"),
    ("syspolicy (Gatekeeper)", "com.apple.syspolicy"),
    ("opendirectoryd", "com.apple.opendirectoryd"),
    ("loginwindow", "com.apple.loginwindow.logging"),
    ("Authorization", "com.apple.Authorization"),
    ("launchservices", "com.apple.launchservices"),
]


_AUTH_VERDICT_SEV = {"malicious": 0, "suspicious": 1, "unknown": 2, "benign": 3}


_AUTH_AGG_WINDOW_HOURS = 24


def auth_events_aggregated(
    session: Session,
    q: str = "",
    subsystem: str = "",
    verdict: str = "",
    sort: str = "count",
    page: int = 1,
    per_page: int = DEFAULT_PER_PAGE,
):
    """Auth events grouped by (content_hash, process, subsystem, event_message),
    joined with LLM verdicts.  Collapses raw log lines into patterns; each
    pattern gets one judgment from the LLM judge.  Supports filtering by
    subsystem, verdict, and free-text search, and sorting by count or verdict
    severity."""
    empty = {
        "rows": [],
        "summary": {},
        "subsystem_options": AUTH_SUBSYSTEM_OPTIONS,
        "total": 0,
        "total_events": 0,
        "page": 1,
        "per_page": per_page,
        "total_pages": 1,
        "q": q,
        "subsystem": subsystem,
        "verdict": verdict,
        "sort": sort,
    }
    if AuthEventRow.__tablename__ not in _existing_tables(session):
        return empty

    # Bound the aggregation to a recent window on the indexed event_timestamp.
    # auth_events accumulates indefinitely (100k+ rows); without this the
    # GROUP BY scans the whole table on every poll.
    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=_AUTH_AGG_WINDOW_HOURS)
    ).isoformat(timespec="seconds")

    # --- summary counts per subsystem (recent window) ---
    summary_rows = session.execute(
        select(AuthEventRow.subsystem, func.count().label("cnt"))
        .where(AuthEventRow.event_timestamp >= cutoff)
        .group_by(AuthEventRow.subsystem)
        .order_by(func.count().desc())
        .limit(12)
    ).all()
    summary = {
        _AUTH_SUBSYSTEM_LABELS.get(s, (s or "(none)").split(".")[-1]): c
        for s, c in summary_rows
    }
    total_events = sum(summary.values())

    # --- aggregation: one row per unique (content_hash) pattern ---
    conds = [AuthEventRow.event_timestamp >= cutoff]
    if q:
        like = f"%{q}%"
        conds.append(
            or_(
                AuthEventRow.process.ilike(like),
                AuthEventRow.event_message.ilike(like),
            )
        )
    if subsystem:
        conds.append(AuthEventRow.subsystem == subsystem)

    group_cols = (
        AuthEventRow.content_hash,
        AuthEventRow.process,
        AuthEventRow.subsystem,
        AuthEventRow.event_message,
    )
    agg_sub = (
        select(
            *group_cols,
            func.count().label("cnt"),
            func.max(AuthEventRow.event_timestamp).label("last_seen"),
        )
        .group_by(*group_cols)
        .where(*conds)
        if conds
        else select(
            *group_cols,
            func.count().label("cnt"),
            func.max(AuthEventRow.event_timestamp).label("last_seen"),
        ).group_by(*group_cols)
    ).subquery("agg")

    # Join with Judgement so each pattern carries its LLM verdict.
    outer = select(
        agg_sub.c.content_hash,
        agg_sub.c.process,
        agg_sub.c.subsystem,
        agg_sub.c.event_message,
        agg_sub.c.cnt,
        agg_sub.c.last_seen,
        Judgement.verdict,
        Judgement.confidence,
        Judgement.reasoning,
    ).outerjoin(
        Judgement,
        and_(
            Judgement.content_hash == agg_sub.c.content_hash,
            Judgement.collector == "auth_events",
        ),
    )

    if verdict:
        if verdict == "unjudged":
            outer = outer.where(Judgement.verdict.is_(None))
        else:
            outer = outer.where(Judgement.verdict == verdict)

    total = (
        session.execute(select(func.count()).select_from(outer.subquery())).scalar()
        or 0
    )

    per_page = max(1, min(per_page, 200))
    page = max(1, page)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)

    if sort == "verdict":
        sev_case = case(
            _AUTH_VERDICT_SEV,
            value=Judgement.verdict,
            else_=99,
        )
        order_by = (sev_case.asc(), agg_sub.c.cnt.desc())
    else:
        order_by = (agg_sub.c.cnt.desc(),)

    page_stmt = outer.order_by(*order_by).offset((page - 1) * per_page).limit(per_page)

    rows = []
    for ch, proc, sub, msg, cnt, last, verd, conf, reason in session.execute(
        page_stmt
    ).all():
        rows.append(
            {
                "process": Path(proc).name if proc else "—",
                "subsystem": sub or "",
                "subsystem_short": _AUTH_SUBSYSTEM_LABELS.get(
                    sub, (sub or "").split(".")[-1] or "—"
                ),
                "message": msg or "",
                "count": cnt,
                "last_seen": (last or "")[:16].replace("T", " "),
                "verdict": verd,
                "confidence": conf,
                "reasoning": reason,
            }
        )

    return {
        "rows": rows,
        "summary": summary,
        "total_events": total_events,
        "subsystem_options": AUTH_SUBSYSTEM_OPTIONS,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "q": q,
        "subsystem": subsystem,
        "verdict": verdict,
        "sort": sort,
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


def _parse_json_list(raw) -> list:
    """Defensively parse a stored JSON array column; [] on any problem."""
    if not raw:
        return []
    try:
        val = json.loads(raw)
        return val if isinstance(val, list) else []
    except (ValueError, TypeError):
        return []


def _parse_json_obj(raw) -> dict:
    """Defensively parse a stored JSON object column; {} on any problem."""
    if not raw:
        return {}
    try:
        val = json.loads(raw)
        return val if isinstance(val, dict) else {}
    except (ValueError, TypeError):
        return {}
