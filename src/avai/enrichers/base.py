"""Core abstractions for the enrichment layer.

Everything downstream depends only on these types — concrete sources,
the chain, the cache, the indicator extractors. No source module imports
from another source; the chain and the registry are the only things that
know about every enricher.
"""
from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum, unique
from typing import Any, ClassVar, Mapping, Optional

LOG = logging.getLogger("avai.enrichers")


@unique
class IndicatorType(StrEnum):
    """Kinds of artifact an external source can be asked about.

    Adding a new type means: 1) collectors can emit it, 2) at least
    one enricher claims to support it. No silent producers / no silent
    consumers.
    """
    SHA256       = "sha256"
    SHA1         = "sha1"
    MD5          = "md5"
    IPV4         = "ipv4"
    DOMAIN       = "domain"
    URL          = "url"
    CVE          = "cve"
    PACKAGE      = "package"   # e.g. "openssl@3.0.2"
    OS_VERSION   = "os_version"  # e.g. "macos@14.4" / "debian@12"


@unique
class VerdictHint(StrEnum):
    """Coarse signal an enricher contributes toward the LLM verdict."""
    MALICIOUS  = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN     = "benign"     # e.g. NSRL whitelist hit
    UNKNOWN    = "unknown"


@dataclass(frozen=True)
class Indicator:
    """An artifact extracted from a collector row.

    ``value`` is canonicalised at construction (hashes lowercased, URLs
    stripped of fragments, etc.) so the cache key is stable across
    callers. ``context`` is opaque side data — kept so an enricher can
    cross-reference the originating row without having to re-derive it.
    """
    type: IndicatorType
    value: str
    context: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self):
        v = self.value
        if self.type in (IndicatorType.SHA256, IndicatorType.SHA1,
                         IndicatorType.MD5, IndicatorType.IPV4,
                         IndicatorType.DOMAIN, IndicatorType.CVE):
            v = v.lower()
        if self.type is IndicatorType.URL and "#" in v:
            v = v.split("#", 1)[0]
        object.__setattr__(self, "value", v)


@dataclass(frozen=True)
class Evidence:
    """Result of an enricher lookup.

    Persisted as one row in the ``enrichment_evidence`` table per
    (source, indicator). The LLM judge sees the ``summary`` field plus
    the ``verdict_hint`` and ``confidence`` — ``details`` is opaque
    JSON for the dashboard.
    """
    source:        str
    indicator:     Indicator
    verdict_hint:  VerdictHint
    confidence:    float
    summary:       str
    details:       Mapping[str, Any] = field(default_factory=dict)
    fetched_at:    datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class EnricherError(Exception):
    """Base of all enricher-side problems. Chain catches and logs."""


class RateLimitedError(EnricherError):
    """Source replied with 429 or equivalent. Caller should back off."""


class Enricher(ABC):
    """One source of threat intel.

    Subclasses set ``name``, ``supports_types``, optionally
    ``requires_token`` (env var that gates registration), ``ttl_hours``
    (cache freshness), and implement ``_fetch()``. The framework
    handles caching, rate-limit handling, and supports-check.
    """

    name:            ClassVar[str]
    supports_types:  ClassVar[frozenset[IndicatorType]]
    requires_token:  ClassVar[Optional[str]] = None
    ttl_hours:       ClassVar[int] = 24

    @classmethod
    def env_token(cls) -> Optional[str]:
        """Return the gate value for this enricher's registration.

        Contract:
            - ``requires_token is None`` (keyless source) → returns
              a fixed non-empty sentinel; the enricher is always
              registered.
            - ``requires_token`` set + env var unset → returns ``None``.
            - ``requires_token`` set + env var present but empty → also
              returns ``None``. Empty strings are common when users
              clear a key via ``-e VAR=`` in docker; treating them as
              "missing" prevents an enricher from running with no key.
            - ``requires_token`` set + env var non-empty → returns it.
        """
        if cls.requires_token is None:
            return "(no token required)"
        return os.environ.get(cls.requires_token, "") or None

    @classmethod
    def from_env(cls) -> Optional["Enricher"]:
        """Factory: return an instance, or ``None`` if the env-gated
        token is required but missing. Concrete subclasses override
        only if they need extra init args."""
        token = cls.env_token()
        if token is None:
            return None
        return cls()

    def supports(self, indicator: Indicator) -> bool:
        return indicator.type in self.supports_types

    @abstractmethod
    def _fetch(self, indicator: Indicator) -> Optional[Evidence]:
        """Hit the network. Return ``None`` for "no opinion" (e.g.
        404 / explicitly-unknown). Raise ``RateLimitedError`` on 429.
        Raise any other exception for transport / parse errors — the
        chain logs them and moves on without poisoning the cache.
        """

    def freshness_cutoff(self) -> datetime:
        return datetime.now(timezone.utc) - timedelta(hours=self.ttl_hours)


# Convenience: the verdict hint priority order. Used by the chain to
# downgrade conflicting evidence to the worst case (a malicious hit on
# any source wins over a benign hit on another).
_HINT_PRIORITY = {
    VerdictHint.MALICIOUS:  3,
    VerdictHint.SUSPICIOUS: 2,
    VerdictHint.UNKNOWN:    1,
    VerdictHint.BENIGN:     0,
}


def worst_hint(hints: list[VerdictHint]) -> VerdictHint:
    """Aggregate multiple evidence hints to the worst-case verdict."""
    if not hints:
        return VerdictHint.UNKNOWN
    return max(hints, key=_HINT_PRIORITY.get)
