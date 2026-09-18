"""Shared pieces of the query layer: collector registry, display fields,
paging, schema probes and the verdict join every panel builds on."""

from __future__ import annotations

import json
import time

from sqlalchemy import (
    and_,
    literal,
    select,
    text,
)
from sqlalchemy.orm import Session

from avai.host_monitor import (
    Judgement,
    slices,
)

COLLECTOR_MODELS = {s.name: s.model for s in slices.ALL}


DISPLAY_FIELDS: dict[str, tuple[str, ...]] = {
    "processes": ("name", "exe"),
    "network_connections": ("raddr_ip", "raddr_port"),
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
    "file_scan": ("rule", "path"),
    "installed_apps": ("name", "bundle_id"),
    # Phase 4
    "process_exec_events": ("exe_path", "parent_path"),
    "mounts": ("mountpoint", "device", "fstype"),
    "setuid_files": ("path",),
    "mdm_profiles": ("display_name", "organization"),
    "kernel_extensions": ("bundle_id", "name"),
    "system_extensions": ("bundle_id", "team_id"),
    "host_resources": (),
    "disk_usage": ("mountpoint", "device", "fstype"),
}


VERDICTS = ("malicious", "suspicious", "unknown", "benign")


PER_PAGE_OPTIONS = (10, 25, 50, 100)


DEFAULT_PER_PAGE = 10


_HIDDEN_SOURCE_FIELDS = {"id", "run_id"}


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


_FLOW_SEV = {"malicious": 0, "suspicious": 1, "unknown": 2, "benign": 3, None: 4}


def _paginate(rows: list, page: int, per_page: int) -> tuple[list, int, int]:
    """Slice *rows* for the requested page. Returns (page_rows, total, total_pages)."""
    total = len(rows)
    per_page = max(1, min(per_page, 200))
    page = max(1, page)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    return rows[(page - 1) * per_page : page * per_page], total, total_pages


def _port_sort_key(p: str):
    """Sort '443/https' or '4444' numerically by the leading port."""
    head = p.split("/", 1)[0]
    return int(head) if head.isdigit() else 0


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
