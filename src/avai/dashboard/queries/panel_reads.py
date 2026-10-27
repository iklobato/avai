"""Shared pieces of the query layer: collector registry, display fields,
paging, schema probes and the verdict join every panel builds on."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, replace
from typing import Any, ClassVar, NamedTuple

from sqlalchemy import and_, literal, select, text
from sqlalchemy.orm import Session

from avai.host_monitor import Judgement
from avai.host_monitor.enums import Verdict
from avai.host_monitor.models import _RowBase
from avai.host_monitor.slices import Slices

# (collector, the fields that name its artifact on a finding)
DISPLAY_FIELDS = (
    ("processes", ("name", "exe")),
    ("network_connections", ("raddr_ip", "raddr_port")),
    ("network_flows", ("dst_ip", "dst_port")),
    ("dns_queries", ("qname", "qtype")),
    ("ssh_authorized_keys", ("owner", "fingerprint")),
    ("hosts_file", ("ip", "hostnames")),
    ("privilege_config", ("kind", "subject")),
    ("listening_ports", ("process_name", "laddr_port")),
    ("usb_devices", ("name", "manufacturer")),
    ("bluetooth_devices", ("name",)),
    ("wifi_state", ("ssid",)),
    ("launch_items", ("label", "path")),
    ("quarantine_events", ("agent_name", "origin_url")),
    ("browser_extensions", ("name", "browser")),
    ("system_integrity", ()),
    ("file_integrity", ("path",)),
    ("file_scan", ("rule", "path")),
    ("installed_apps", ("name", "bundle_id")),
    ("process_exec_events", ("exe_path", "parent_path")),
    ("mounts", ("mountpoint", "device", "fstype")),
    ("setuid_files", ("path",)),
    ("mdm_profiles", ("display_name", "organization")),
    ("kernel_extensions", ("bundle_id", "name")),
    ("system_extensions", ("bundle_id", "team_id")),
    ("host_resources", ()),
    ("disk_usage", ("mountpoint", "device", "fstype")),
)

PER_PAGE_OPTIONS = (10, 25, 50, 100)

DEFAULT_PER_PAGE = 10

MAX_PER_PAGE = 200

HIDDEN_SOURCE_FIELDS = frozenset({"id", "run_id"})


class CollectorTables:
    """Collector name to the ORM model of the table it writes."""

    def models(self) -> dict[str, type[_RowBase]]:
        return {item.name: item.model for item in Slices.ALL}

    def model(self, collector: str) -> type[_RowBase] | None:
        return self.models().get(collector)


class SchemaProbe:
    """Which tables and columns the DB actually has. The dashboard may read
    a database written by an *older* monitor that predates a collector or
    a column, so querying it would 500; callers check here and degrade
    gracefully instead. Answers are cached per DB for a short while."""

    TTL_S = 30.0
    _tables_cache: ClassVar[dict[str, tuple[float, set[str]]]] = {}
    _columns_cache: ClassVar[dict[tuple[str, str], tuple[float, set[str]]]] = {}

    def __init__(self, session: Session) -> None:
        self._session = session

    def tables(self) -> set[str]:
        key = str(self._session.get_bind().url)
        hit = self._tables_cache.get(key)
        if hit is not None and time.monotonic() - hit[0] < self.TTL_S:
            return hit[1]
        statement = text("SELECT name FROM sqlite_master WHERE type='table'")
        tables = set(self._session.execute(statement).scalars())
        self._tables_cache[key] = (time.monotonic(), tables)
        return tables

    def columns(self, table: str) -> set[str]:
        key = (str(self._session.get_bind().url), table)
        hit = self._columns_cache.get(key)
        if hit is not None and time.monotonic() - hit[0] < self.TTL_S:
            return hit[1]
        rows = self._session.execute(text(f"PRAGMA table_info({table})")).all()
        columns = {row[1] for row in rows}  # row[1] is the column name
        self._columns_cache[key] = (time.monotonic(), columns)
        return columns


class FindingSource:
    """The collector row a judgment was made on."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def row_and_artifact(self, judgment: Judgement) -> tuple[dict[str, Any], str]:
        """The *most recent* observation of the judgment's content_hash in its
        collector table (the artifact's latest state, not the row from the
        run it was first judged in), and its display label."""
        model = CollectorTables().model(judgment.collector)
        if model is None:
            return {}, ""
        statement = (
            select(model)
            .where(model.content_hash == judgment.content_hash)
            .order_by(model.collected_at.desc())
            .limit(1)
        )
        row_obj = self._session.execute(statement).scalar_one_or_none()
        if row_obj is None:
            return {}, ""
        full = self.source_row(row_obj)
        return full, self.artifact_label(judgment.collector, full)

    def source_row(self, row_obj: _RowBase) -> dict[str, Any]:
        """A collector row as a dict, minus the internal SQL plumbing columns."""
        columns = row_obj.__table__.columns
        return {
            column.name: getattr(row_obj, column.name)
            for column in columns
            if column.name not in HIDDEN_SOURCE_FIELDS
        }

    def artifact_label(self, collector: str, source_row: dict[str, Any]) -> str:
        """The short "what is this" text for a finding, from its display fields."""
        fields = dict(DISPLAY_FIELDS).get(collector, ())
        shown = (
            source_row[name]
            for name in fields
            if source_row.get(name) not in (None, "")
        )
        return " · ".join(str(value) for value in shown)


class VerdictRank:
    """Orders verdicts worst first; anything unrecognised sorts last."""

    def rank(self, verdict: str | None) -> int:
        ranks = Verdict.ranks()
        return ranks.get(verdict or "", len(ranks))

    def take_worse(
        self, group: dict[str, Any], judged: tuple[str | None, Any, str | None]
    ) -> None:
        """Keep the worst ``(verdict, confidence, reasoning)`` a grouped row
        has seen."""
        verdict, confidence, reasoning = judged
        if self.rank(verdict) < self.rank(group["verdict"]):
            group["verdict"] = verdict
            group["confidence"] = confidence
            group["reasoning"] = reasoning or ""


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

    def fields(self, total: int) -> dict[str, int]:
        """The pagination keys every panel returns, for ``total`` rows."""
        page = self.within(total)
        return {
            "total": total,
            "page": page.number,
            "per_page": page.size,
            "total_pages": page.total_pages(total),
        }

    def slice(self, rows: list[Any]) -> tuple[list[Any], dict[str, int]]:
        """The rows on this page, plus :meth:`fields` for all of ``rows``."""
        page = self.within(len(rows))
        return rows[page.offset : page.offset + page.size], self.fields(len(rows))


class PortLabel:
    def sort_key(self, label: str) -> int:
        """Sort '443/https' or '4444' numerically by the leading port."""
        head = label.split("/", 1)[0]
        return int(head) if head.isdigit() else 0


class ColumnPicker:
    """Selects a model's columns, reading a column an older monitor never
    wrote as NULL instead of failing the query."""

    def __init__(self, model: type[_RowBase], present: set[str]) -> None:
        self._model = model
        self._present = present

    def column(self, name: str) -> Any:
        if name in self._present:
            return getattr(self._model, name)
        return literal(None).label(name)


class VerdictTable(NamedTuple):
    """One collector table as a panel shows it: the columns it reads, the ones
    the search box looks in, and how many rows it reads at most."""

    collector: str
    columns: tuple[str, ...]
    search: tuple[str, ...]
    limit: int = 500

    def rows(self, session: Session, run_id: str) -> list[dict[str, Any]]:
        """Every row for ``run_id``, each annotated with its LLM verdict (LEFT
        JOIN Judgement on content_hash), worst verdict first. A missing newer
        column reads as NULL and a missing table returns ``[]``."""
        model = CollectorTables().models()[self.collector]
        probe = SchemaProbe(session)
        if model.__tablename__ not in probe.tables():
            return []
        picker = ColumnPicker(model, probe.columns(model.__tablename__))
        statement = self._statement(model, picker).where(model.run_id == run_id)
        rows = [self._row(row) for row in session.execute(statement).all()]
        return sorted(rows, key=self._severity)

    def _statement(self, model: type[_RowBase], picker: ColumnPicker) -> Any:
        judged = and_(
            Judgement.content_hash == model.content_hash,
            Judgement.collector == self.collector,
        )
        return (
            select(
                *(picker.column(name) for name in self.columns),
                Judgement.verdict,
                Judgement.confidence,
                Judgement.reasoning,
            )
            .outerjoin(Judgement, judged)
            .limit(self.limit)
        )

    def _row(self, row: Any) -> dict[str, Any]:
        width = len(self.columns)
        values = dict(zip(self.columns, row[:width]))
        verdict, confidence, reasoning = row[width:]
        return {
            **values,
            "verdict": verdict,
            "confidence": confidence,
            "reasoning": reasoning,
        }

    def _severity(self, row: dict[str, Any]) -> int:
        return VerdictRank().rank(row["verdict"])


@dataclass(frozen=True)
class RowFilter:
    """The verdict pick and search box most panels share."""

    verdict: str = ""
    search: str = ""

    def keep(
        self, rows: list[dict[str, Any]], columns: tuple[str, ...]
    ) -> list[dict[str, Any]]:
        """``rows`` with the picked verdict whose ``columns`` hold the search
        text (case-insensitive)."""
        kept = [
            row
            for row in rows
            if not self.verdict or row.get("verdict") == self.verdict
        ]
        if not self.search:
            return kept
        needle = self.search.lower()
        return [
            row
            for row in kept
            if any(needle in str(row.get(key) or "").lower() for key in columns)
        ]

    def fields(self) -> dict[str, str]:
        """The filter values a panel echoes back to its form."""
        return {"verdict": self.verdict, "q": self.search}


class VerdictTally:
    def of(self, rows: list[dict[str, Any]]) -> dict[str, int]:
        """Row count plus how many of them the judge flagged."""
        verdicts = [row["verdict"] for row in rows]
        return {
            "total": len(rows),
            Verdict.MALICIOUS.value: verdicts.count(Verdict.MALICIOUS),
            Verdict.SUSPICIOUS.value: verdicts.count(Verdict.SUSPICIOUS),
        }


class VerdictPanel:
    """A panel of small, bounded tables shown whole (no paging) behind one
    shared verdict + search filter, with per-table counts for the header."""

    def __init__(self, session: Session, run_id: str) -> None:
        self._session = session
        self._run_id = run_id

    def tables(
        self, tables: dict[str, VerdictTable], filters: RowFilter
    ) -> dict[str, Any]:
        rows = {
            name: filters.keep(table.rows(self._session, self._run_id), table.search)
            for name, table in tables.items()
        }
        return {
            **rows,
            "counts": {name: VerdictTally().of(found) for name, found in rows.items()},
            **filters.fields(),
            "any": any(rows.values()),
        }


class StoredJson:
    """Defensively parse a stored JSON column."""

    def as_list(self, raw: str | None) -> list[Any]:
        value = self._loads(raw)
        return value if isinstance(value, list) else []

    def as_dict(self, raw: str | None) -> dict[str, Any]:
        value = self._loads(raw)
        return value if isinstance(value, dict) else {}

    def _loads(self, raw: str | None) -> Any | None:
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return None
