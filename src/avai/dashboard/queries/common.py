"""Shared pieces of the query layer: collector registry, display fields,
paging, schema probes and the verdict join every panel builds on."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, replace
from typing import NamedTuple

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


def _source_row(row_obj) -> dict:
    """A collector row as a dict, minus the internal SQL plumbing columns."""
    return {
        col.name: getattr(row_obj, col.name)
        for col in row_obj.__table__.columns
        if col.name not in _HIDDEN_SOURCE_FIELDS
    }


def _artifact_label(collector: str, source_row: dict) -> str:
    """The short "what is this" text for a finding, from its display fields."""
    fields = DISPLAY_FIELDS.get(collector, ())
    return " · ".join(
        str(source_row[f]) for f in fields if source_row.get(f) not in (None, "")
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
    full = _source_row(row_obj)
    return full, _artifact_label(j.collector, full)


_FLOW_SEV = {"malicious": 0, "suspicious": 1, "unknown": 2, "benign": 3, None: 4}


MAX_PER_PAGE = 200


@dataclass(frozen=True)
class Page:
    """One page of a panel as the query string asked for it. Clamped on
    construction, so a hand-typed ``?page=0`` or ``?per_page=999`` still
    names a real page."""

    number: int = 1
    size: int = DEFAULT_PER_PAGE

    def __post_init__(self) -> None:
        object.__setattr__(self, "number", max(1, self.number))
        object.__setattr__(self, "size", max(1, min(self.size, MAX_PER_PAGE)))

    def total_pages(self, total: int) -> int:
        return max(1, (total + self.size - 1) // self.size)

    def within(self, total: int) -> Page:
        """This page, pulled back to the last one when ``total`` rows don't
        reach it. Without the upper bound a huge ``?page=`` builds an OFFSET
        past SQLite's 64-bit INTEGER range and raises OverflowError."""
        return replace(self, number=min(self.number, self.total_pages(total)))

    @property
    def offset(self) -> int:
        return (self.number - 1) * self.size

    def fields(self, total: int) -> dict:
        """The pagination keys every panel returns, for ``total`` rows."""
        page = self.within(total)
        return {
            "total": total,
            "page": page.number,
            "per_page": page.size,
            "total_pages": page.total_pages(total),
        }

    def slice(self, rows: list) -> tuple[list, dict]:
        """The rows on this page, plus :meth:`fields` for all of ``rows``."""
        page = self.within(len(rows))
        return rows[page.offset : page.offset + page.size], self.fields(len(rows))


def _port_sort_key(p: str):
    """Sort '443/https' or '4444' numerically by the leading port."""
    head = p.split("/", 1)[0]
    return int(head) if head.isdigit() else 0


def _column_or_null(model, name: str, present: set[str]):
    """``model.name``, or a NULL labelled ``name`` when an older monitor wrote
    the table before that column existed (selecting it would 500)."""
    return getattr(model, name) if name in present else literal(None).label(name)


class VerdictTable(NamedTuple):
    """One collector table as a panel shows it: the columns it reads, the ones
    the search box looks in, and how many rows it reads at most."""

    collector: str
    columns: tuple[str, ...]
    search: tuple[str, ...]
    limit: int = 500

    def rows(self, session: Session, run_id: str) -> list[dict]:
        """Every row for ``run_id``, each annotated with its LLM verdict (LEFT
        JOIN Judgement on content_hash), worst verdict first. A missing newer
        column reads as NULL and a missing table returns ``[]``."""
        model = COLLECTOR_MODELS[self.collector]
        if model.__tablename__ not in _existing_tables(session):
            return []
        present = _existing_columns(session, model.__tablename__)
        stmt = (
            select(
                *(_column_or_null(model, c, present) for c in self.columns),
                Judgement.verdict,
                Judgement.confidence,
                Judgement.reasoning,
            )
            .outerjoin(
                Judgement,
                and_(
                    Judgement.content_hash == model.content_hash,
                    Judgement.collector == self.collector,
                ),
            )
            .where(model.run_id == run_id)
            .limit(self.limit)
        )
        n = len(self.columns)
        out = []
        for row in session.execute(stmt).all():
            d = dict(zip(self.columns, row[:n]))
            d["verdict"], d["confidence"], d["reasoning"] = row[n : n + 3]
            out.append(d)
        out.sort(key=lambda r: _FLOW_SEV.get(r["verdict"], 4))
        return out


@dataclass(frozen=True)
class RowFilter:
    """The verdict pick and search box most panels share."""

    verdict: str = ""
    q: str = ""

    def keep(self, rows: list[dict], search: tuple[str, ...]) -> list[dict]:
        """``rows`` with the picked verdict whose ``search`` fields hold ``q``
        (case-insensitive)."""
        if self.verdict:
            rows = [r for r in rows if r.get("verdict") == self.verdict]
        if self.q:
            needle = self.q.lower()
            rows = [
                r
                for r in rows
                if any(needle in str(r.get(k) or "").lower() for k in search)
            ]
        return rows

    def fields(self) -> dict:
        """The filter values a panel echoes back to its form."""
        return {"verdict": self.verdict, "q": self.q}


def _tally(rows: list[dict]) -> dict:
    """Row count plus how many of them the judge flagged."""
    return {
        "total": len(rows),
        "malicious": sum(1 for r in rows if r["verdict"] == "malicious"),
        "suspicious": sum(1 for r in rows if r["verdict"] == "suspicious"),
    }


def _verdict_tables(
    session: Session,
    run_id: str,
    tables: dict[str, VerdictTable],
    filters: RowFilter,
) -> dict:
    """A panel of small, bounded tables shown whole (no paging) behind one
    shared verdict + search filter, with per-table counts for the header."""
    rows = {
        name: filters.keep(table.rows(session, run_id), table.search)
        for name, table in tables.items()
    }
    return {
        **rows,
        "counts": {name: _tally(r) for name, r in rows.items()},
        **filters.fields(),
        "any": any(rows.values()),
    }


def _take_worse_verdict(group: dict, verdict, confidence, reasoning) -> None:
    """Keep the worst verdict a grouped row has seen, with its reasoning."""
    if _FLOW_SEV.get(verdict, 4) < _FLOW_SEV.get(group["verdict"], 4):
        group["verdict"] = verdict
        group["confidence"] = confidence
        group["reasoning"] = reasoning or ""


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
