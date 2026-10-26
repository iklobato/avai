"""SQLite-backed TTL cache for enrichment evidence.

One row per ``(source, indicator_type, indicator_value)``. Lookups
honour each enricher's ``ttl_hours`` — an expired row is treated as a
miss without being deleted (keeps history for the dashboard's
"evidence over time" view).

The model lives in :mod:`avai.host_monitor`'s ``Base.metadata`` so the
Runner's ``Base.metadata.create_all()`` picks it up — no separate
migration story.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import Engine, String, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from avai.enrichers.base import Enricher, Evidence, Indicator, VerdictHint

EVIDENCE_TABLE = "enrichment_evidence"
KEY_COLUMNS = ("source", "indicator_type", "indicator_value")
UPDATED_COLUMNS = (
    "verdict_hint",
    "confidence",
    "summary",
    "details_json",
    "fetched_at",
)
NO_CONFIDENCE = 0.0


class EnrichmentSchema:
    """Defines the enrichment ORM model on a declarative base, once.

    The class is defined lazily so this module imports without pulling
    host_monitor (host_monitor imports us back through the cache
    plumbing). Production only uses one ``Base``; tests create throwaway
    bases per fixture, so the model is looked up on the base's own
    registry instead of a process-wide one. Call ``model()`` at startup
    before ``metadata.create_all()`` so the table exists even when the
    enrichment chain isn't running on this process (the dashboard still
    reads from it)."""

    def __init__(self, base_cls: type[DeclarativeBase]) -> None:
        self._base_cls = base_cls

    def model(self) -> type[Any]:
        for mapper in self._base_cls.registry.mappers:
            if mapper.local_table.name == EVIDENCE_TABLE:
                return mapper.class_
        # The registry holds mapped classes weakly: once a class is collected
        # its table stays on the metadata, so map a new class onto that table.
        existing = self._base_cls.metadata.tables.get(EVIDENCE_TABLE)
        if existing is not None:
            return type("EnrichmentRow", (self._base_cls,), {"__table__": existing})
        return self._define()

    def _define(self) -> type[Any]:
        class EnrichmentRow(self._base_cls):
            __tablename__ = EVIDENCE_TABLE

            # Composite primary key — one row per (source, indicator) pair.
            source: Mapped[str] = mapped_column(String, primary_key=True)
            indicator_type: Mapped[str] = mapped_column(String, primary_key=True)
            # Indexed: the dashboard's flow-geo lookup filters by
            # indicator_value IN (...); the composite PK leads with `source`,
            # so that filter can't use the autoindex.
            indicator_value: Mapped[str] = mapped_column(
                String, primary_key=True, index=True
            )
            verdict_hint: Mapped[str] = mapped_column(String)
            confidence: Mapped[float] = mapped_column()
            summary: Mapped[str] = mapped_column(String)
            details_json: Mapped[str] = mapped_column(String)
            fetched_at: Mapped[str] = mapped_column(String)  # ISO-8601 UTC

        return EnrichmentRow


class EvidenceCache:
    """Repository over the ``enrichment_evidence`` table.

    Thread-safe by virtue of SQLAlchemy session-per-call; rate of
    contention is low (one cache write per indicator per source per
    cycle, typically <100 / minute).
    """

    def __init__(self, engine: Engine, model: type[Any]) -> None:
        self._engine = engine
        self._model = model

    @classmethod
    def on_base(cls, engine: Engine, base_cls: type[DeclarativeBase]) -> EvidenceCache:
        return cls(engine, EnrichmentSchema(base_cls).model())

    def get(self, enricher: Enricher, indicator: Indicator) -> Evidence | None:
        """Return cached evidence iff it's within ``enricher.ttl_hours``."""
        cutoff = enricher.freshness_cutoff().isoformat(timespec="seconds")
        stmt = select(self._model).where(
            self._model.source == enricher.name,
            self._model.indicator_type == str(indicator.type),
            self._model.indicator_value == indicator.value,
            self._model.fetched_at >= cutoff,
        )
        with Session(self._engine) as session:
            row = session.execute(stmt).scalar_one_or_none()
        if row is None:
            return None
        return CachedEvidence(row).to_evidence(indicator)

    def put(self, evidence: Evidence) -> None:
        """Upsert. Conflict on the (source, type, value) PK overwrites
        the older row — we want the freshest evidence per pair."""
        payload = self._payload(evidence)
        stmt = (
            sqlite_insert(self._model)
            .values(**payload)
            .on_conflict_do_update(
                index_elements=list(KEY_COLUMNS),
                set_={column: payload[column] for column in UPDATED_COLUMNS},
            )
        )
        with Session(self._engine) as session:
            session.execute(stmt)
            session.commit()

    def _payload(self, evidence: Evidence) -> dict[str, Any]:
        return {
            "source": evidence.source,
            "indicator_type": str(evidence.indicator.type),
            "indicator_value": evidence.indicator.value,
            "verdict_hint": str(evidence.verdict_hint),
            "confidence": evidence.confidence,
            "summary": evidence.summary,
            "details_json": json.dumps(evidence.details, default=str),
            "fetched_at": evidence.fetched_at.isoformat(timespec="seconds"),
        }


class CachedEvidence:
    """One stored ``enrichment_evidence`` row read back as Evidence."""

    def __init__(self, row: Any) -> None:
        self._row = row

    def to_evidence(self, indicator: Indicator) -> Evidence:
        return Evidence(
            source=self._row.source,
            indicator=indicator,
            verdict_hint=VerdictHint(self._row.verdict_hint),
            confidence=float(self._row.confidence or NO_CONFIDENCE),
            summary=self._row.summary or "",
            details=self._details(),
            fetched_at=datetime.fromisoformat(self._row.fetched_at),
        )

    def _details(self) -> dict[str, Any]:
        if not self._row.details_json:
            return {}
        try:
            return json.loads(self._row.details_json)
        except json.JSONDecodeError:
            return {}
