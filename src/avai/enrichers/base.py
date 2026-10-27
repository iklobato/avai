"""Core abstractions for the enrichment layer.

Everything downstream depends only on these types — concrete sources,
the chain, the cache, the indicator extractors. No source module imports
from another source; the chain and the registry are the only things that
know about every enricher.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum, unique
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, ClassVar, Mapping

from avai.errors import AvaiError

if TYPE_CHECKING:
    import requests

    from avai.enrichers.http import HttpClient

# CVSS v3 severity bands: critical from 9.0, high from 7.0.
CVSS_CRITICAL = 9.0
CVSS_HIGH = 7.0
DEFAULT_TTL_HOURS = 24
DEFAULT_SOURCE_RATE_PER_SECOND = 1.0
# Gate value of a keyless source: non-empty so it always registers.
KEYLESS_TOKEN = "(no token required)"


@unique
class IndicatorType(StrEnum):
    """Kinds of artifact an external source can be asked about.

    Adding a new type means: 1) collectors can emit it, 2) at least
    one enricher claims to support it. No silent producers / no silent
    consumers.
    """

    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    CVE = "cve"
    PACKAGE = "package"  # e.g. "openssl@3.0.2"
    OS_VERSION = "os_version"  # e.g. "macos@14.4" / "debian@12"


@unique
class VerdictHint(StrEnum):
    """Coarse signal an enricher contributes toward the LLM verdict."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"  # e.g. NSRL whitelist hit
    UNKNOWN = "unknown"

LOWERCASED_TYPES = frozenset(
    {
        IndicatorType.SHA256,
        IndicatorType.SHA1,
        IndicatorType.MD5,
        IndicatorType.IPV4,
        IndicatorType.IPV6,
        IndicatorType.DOMAIN,
        IndicatorType.CVE,
    }
)


@dataclass(frozen=True)
class Indicator:
    """An artifact extracted from a collector row.

    ``value`` is canonicalised at construction (hashes lowercased, URLs
    stripped of fragments, etc.) so the cache key is stable across
    callers.
    """

    type: IndicatorType
    value: str

    def __post_init__(self) -> None:
        canonical = self.value
        if self.type in LOWERCASED_TYPES:
            canonical = canonical.lower()
        if self.type is IndicatorType.URL and "#" in canonical:
            canonical = canonical.split("#", 1)[0]
        object.__setattr__(self, "value", canonical)


@dataclass(frozen=True)
class Verdict:
    """A source's hint plus how much it trusts that hint."""

    hint: VerdictHint
    confidence: float


@dataclass(frozen=True)
class Evidence:
    """Result of an enricher lookup.

    Persisted as one row in the ``enrichment_evidence`` table per
    (source, indicator). The LLM judge sees the ``summary`` field plus
    the ``verdict_hint`` and ``confidence`` — ``details`` is opaque
    JSON for the dashboard.
    """

    source: str
    indicator: Indicator
    verdict_hint: VerdictHint
    confidence: float
    summary: str
    details: Mapping[str, Any] = field(default_factory=dict)
    fetched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class EnricherError(AvaiError):
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

    name: ClassVar[str]
    supports_types: ClassVar[frozenset[IndicatorType]]
    requires_token: ClassVar[str | None] = None
    ttl_hours: ClassVar[int] = DEFAULT_TTL_HOURS
    # Host whose per-host rate limit this source sets on the shared client.
    rate_host: ClassVar[str | None] = None
    rate_per_second: ClassVar[float] = DEFAULT_SOURCE_RATE_PER_SECOND

    def __init__(self, http: HttpClient, token: str) -> None:
        self._http = http
        self._token = token

    @classmethod
    def env_token(cls, env: Mapping[str, str]) -> str | None:
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
            return KEYLESS_TOKEN
        return env.get(cls.requires_token, "") or None

    @classmethod
    def create(cls, http: HttpClient, env: Mapping[str, str]) -> Enricher | None:
        """Factory: return an instance, or ``None`` if the env-gated
        token is required but missing. Sets this source's rate limit on
        the shared client."""
        token = cls.env_token(env)
        if token is None:
            return None
        if cls.rate_host is not None:
            http.set_rate(cls.rate_host, cls.rate_per_second)
        return cls(http, token)

    def supports(self, indicator: Indicator) -> bool:
        return indicator.type in self.supports_types

    @abstractmethod
    def fetch(self, indicator: Indicator) -> Evidence | None:
        """Hit the network. Return ``None`` for "no opinion" (e.g.
        404 / explicitly-unknown). Raise ``RateLimitedError`` on 429.
        Raise any other exception for transport / parse errors — the
        chain logs them and moves on without poisoning the cache.
        """

    def answered(self, response: requests.Response) -> bool:
        """True for a 200, False for a 404 (the source has nothing on the
        indicator). Any other status (a bad key, a server error) is raised,
        so the chain logs it instead of reading it as "no opinion"."""
        if response.status_code == HTTPStatus.NOT_FOUND:
            return False
        if response.status_code != HTTPStatus.OK:
            raise EnricherError(f"{self.name} returned {int(response.status_code)}")
        return True

    def freshness_cutoff(self) -> datetime:
        return datetime.now(timezone.utc) - timedelta(hours=self.ttl_hours)
