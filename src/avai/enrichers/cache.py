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
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import Engine, String, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Mapped, Session, mapped_column

from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    VerdictHint,
)

LOG = logging.getLogger("avai.enrichers.cache")


def _register_model(base_cls):
    """Defer the ORM class definition so this module can import without
    pulling host_monitor at import time (host_monitor imports us back
    through the cache plumbing). The Runner calls this once at startup."""

    class EnrichmentRow(base_cls):
        __tablename__ = "enrichment_evidence"

        # Composite primary key — one row per (source, indicator) pair.
        source:           Mapped[str] = mapped_column(String, primary_key=True)
        indicator_type:   Mapped[str] = mapped_column(String, primary_key=True)
        indicator_value:  Mapped[str] = mapped_column(String, primary_key=True)
        verdict_hint:     Mapped[str] = mapped_column(String)
        confidence:       Mapped[float] = mapped_column()
        summary:          Mapped[str] = mapped_column(String)
        details_json:     Mapped[str] = mapped_column(String)
        fetched_at:       Mapped[str] = mapped_column(String)  # ISO-8601 UTC

    return EnrichmentRow


# Per-base registry. Production only ever uses one ``Base`` (the one
# in host_monitor); but tests create throwaway DeclarativeBase classes
# per fixture, so a single global model would either collide on the
# second register or get attached to the wrong metadata. Keying by
# ``base_cls`` avoids both.
_MODELS: dict[type, type] = {}


def register_schema(base_cls) -> type:
    """Idempotently register the enrichment ORM model against
    ``base_cls`` and return the class. Call this at startup before
    ``base_cls.metadata.create_all()`` so the table exists even when
    the enrichment chain isn't running on this process (the dashboard
    still reads from it)."""
    if base_cls not in _MODELS:
        _MODELS[base_cls] = _register_model(base_cls)
    return _MODELS[base_cls]


def get_model(base_cls=None):
    """Return the ORM class registered against ``base_cls`` (preferred),
    or — for callers that only ever use one Base — any registered class.
    Returns ``None`` if nothing's been registered yet."""
    if base_cls is not None:
        return _MODELS.get(base_cls)
    if not _MODELS:
        return None
    return next(iter(_MODELS.values()))


class EvidenceCache:
    """Repository over the ``enrichment_evidence`` table.

    Thread-safe by virtue of SQLAlchemy session-per-call; rate of
    contention is low (one cache write per indicator per source per
    cycle, typically <100 / minute).
    """

    def __init__(self, engine: Engine, base_cls):
        self._engine = engine
        self._model = register_schema(base_cls)

    # -- core API --------------------------------------------------------

    def get(self, enricher: Enricher,
            indicator: Indicator) -> Optional[Evidence]:
        """Return cached evidence iff it's within ``enricher.ttl_hours``."""
        cutoff = enricher.freshness_cutoff().isoformat(timespec="seconds")
        stmt = select(self._model).where(
            self._model.source          == enricher.name,
            self._model.indicator_type  == str(indicator.type),
            self._model.indicator_value == indicator.value,
            self._model.fetched_at      >= cutoff,
        )
        with Session(self._engine) as session:
            row = session.execute(stmt).scalar_one_or_none()
        if row is None:
            return None
        return _evidence_from_row(row, indicator)

    def put(self, evidence: Evidence) -> None:
        """Upsert. Conflict on the (source, type, value) PK overwrites
        the older row — we want the freshest evidence per pair."""
        payload = {
            "source":          evidence.source,
            "indicator_type":  str(evidence.indicator.type),
            "indicator_value": evidence.indicator.value,
            "verdict_hint":    str(evidence.verdict_hint),
            "confidence":      evidence.confidence,
            "summary":         evidence.summary,
            "details_json":    json.dumps(evidence.details, default=str),
            "fetched_at":      evidence.fetched_at.isoformat(timespec="seconds"),
        }
        stmt = sqlite_insert(self._model).values(**payload)
        stmt = stmt.on_conflict_do_update(
            index_elements=["source", "indicator_type", "indicator_value"],
            set_={k: payload[k] for k in
                  ("verdict_hint", "confidence", "summary",
                   "details_json", "fetched_at")},
        )
        with Session(self._engine) as session:
            session.execute(stmt)
            session.commit()

    def for_indicator(self, indicator: Indicator) -> list[Evidence]:
        """All persisted evidence for an indicator — across every source.
        Used by the dashboard to render the per-finding evidence panel."""
        stmt = select(self._model).where(
            self._model.indicator_type  == str(indicator.type),
            self._model.indicator_value == indicator.value,
        )
        with Session(self._engine) as session:
            rows = session.execute(stmt).scalars().all()
        return [_evidence_from_row(r, indicator) for r in rows]


def _evidence_from_row(row, indicator: Indicator) -> Evidence:
    try:
        details = json.loads(row.details_json) if row.details_json else {}
    except json.JSONDecodeError:
        details = {}
    return Evidence(
        source       = row.source,
        indicator    = indicator,
        verdict_hint = VerdictHint(row.verdict_hint),
        confidence   = float(row.confidence or 0.0),
        summary      = row.summary or "",
        details      = details,
        fetched_at   = datetime.fromisoformat(row.fetched_at),
    )


# Re-export the ORM class so ``from avai.enrichers import EnrichmentRow``
# works after the Runner has registered the model. Until then it's
# ``None``; the Runner sequences the import correctly.
class _LazyModel:
    """Placeholder so ``from .cache import EnrichmentRow`` doesn't fail
    before the Runner registers the model. Attribute access proxies to
    a registered class once one exists. Production only ever has one
    base; tests may have several but only need one for queries."""

    def __getattr__(self, name):
        model = get_model()
        if model is None:
            raise AttributeError(
                "EnrichmentRow accessed before Runner registered the model"
            )
        return getattr(model, name)


EnrichmentRow = _LazyModel()
