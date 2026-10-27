"""Threat-intel enrichment layer.

Sits between collectors and the LLM judge: extracts indicators
(hashes, IPs, URLs, CVEs, package names) from each new finding,
fans them out to external threat-intel APIs, and persists structured
evidence the judge then references in its prompt.

Public API:
    Indicator, IndicatorType        — what a collector emits
    Evidence, VerdictHint           — what an enricher returns
    Enricher                        — strategy base class
    EnrichmentChain                 — composes all enabled enrichers
    EvidenceCache                   — SQLite-backed TTL cache
    EnrichmentSchema                — ORM persistence of the evidence
    ChainBuilder                    — factory that reads env for keys
    IndicatorExtraction             — per-collector indicator extraction
"""

from __future__ import annotations

from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    VerdictHint,
)
from avai.enrichers.cache import EnrichmentSchema, EvidenceCache
from avai.enrichers.chain import EnrichmentChain
from avai.enrichers.indicators import IndicatorExtraction
from avai.enrichers.registry import ChainBuilder, ChainRequest, EnricherCatalog

__all__ = [
    "ChainBuilder",
    "ChainRequest",
    "Enricher",
    "EnricherCatalog",
    "EnrichmentChain",
    "EnrichmentSchema",
    "Evidence",
    "EvidenceCache",
    "Indicator",
    "IndicatorExtraction",
    "IndicatorType",
    "VerdictHint",
]
