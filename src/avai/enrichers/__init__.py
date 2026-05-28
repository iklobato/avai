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
    EnrichmentRow                   — ORM persistence
    build_default_chain()           — factory that reads env for keys
    extract_indicators(coll, row)   — per-collector indicator extraction
"""
from __future__ import annotations

from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    VerdictHint,
)
from avai.enrichers.cache import EnrichmentRow, EvidenceCache
from avai.enrichers.chain import EnrichmentChain
from avai.enrichers.indicators import extract_indicators
from avai.enrichers.registry import build_default_chain

__all__ = [
    "Enricher",
    "EnrichmentChain",
    "EnrichmentRow",
    "Evidence",
    "EvidenceCache",
    "Indicator",
    "IndicatorType",
    "VerdictHint",
    "build_default_chain",
    "extract_indicators",
]
