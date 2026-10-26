"""VirusTotal v3 — multi-engine reputation for files, URLs, domains, IPs.

Requires ``VT_API_KEY``. Free tier: 4 req/min, 500/day.
https://docs.virustotal.com/reference/files
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, ClassVar

from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    Verdict,
    VerdictHint,
)
from avai.enrichers.http import RequestOptions

BASE_URL = "https://www.virustotal.com/api/v3"
TIMEOUT_S = 12.0
LISTED_NAMES = 5
# Engine-count cut-offs for the hint.
MALICIOUS_ENGINES = 5
MALICIOUS_RATIO = 0.2
SUSPICIOUS_ENGINES = 3
# A clean result only counts as benign when enough engines looked.
BENIGN_MIN_ENGINES = 10
MALICIOUS_CONFIDENCE = 0.95
SUSPICIOUS_CONFIDENCE = 0.7
BENIGN_CONFIDENCE = 0.6
UNKNOWN_CONFIDENCE = 0.3
HASH_TYPES = frozenset({IndicatorType.SHA256, IndicatorType.SHA1, IndicatorType.MD5})
COLLECTION_BY_TYPE = (
    (IndicatorType.IPV4, "ip_addresses"),
    (IndicatorType.DOMAIN, "domains"),
)


@dataclass(frozen=True)
class EngineStats:
    """How many engines flagged the artifact, out of how many looked."""

    malicious: int
    suspicious: int
    total: int

    @classmethod
    def of(cls, stats: Mapping[str, int]) -> EngineStats:
        return cls(
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            total=sum(stats.values()) or 1,
        )

    @property
    def flagged_ratio(self) -> float:
        return (self.malicious + self.suspicious) / self.total

    def verdict(self) -> Verdict:
        if self.malicious >= MALICIOUS_ENGINES or self.flagged_ratio >= MALICIOUS_RATIO:
            return Verdict(VerdictHint.MALICIOUS, MALICIOUS_CONFIDENCE)
        if self.malicious >= 1 or self.suspicious >= SUSPICIOUS_ENGINES:
            return Verdict(VerdictHint.SUSPICIOUS, SUSPICIOUS_CONFIDENCE)
        clean = self.malicious == 0 and self.suspicious == 0
        if self.total >= BENIGN_MIN_ENGINES and clean:
            return Verdict(VerdictHint.BENIGN, BENIGN_CONFIDENCE)
        return Verdict(VerdictHint.UNKNOWN, UNKNOWN_CONFIDENCE)


class VirusTotalEnricher(Enricher):
    name = "virustotal"
    supports_types = frozenset(
        {
            IndicatorType.SHA256,
            IndicatorType.SHA1,
            IndicatorType.MD5,
            IndicatorType.IPV4,
            IndicatorType.DOMAIN,
            IndicatorType.URL,
        }
    )
    requires_token: ClassVar[str | None] = "VT_API_KEY"
    ttl_hours = 24
    rate_host = "www.virustotal.com"
    # Free tier: 4 req / minute → ~0.066 rps. Pad to 0.06 for safety.
    rate_per_second = 0.06

    def api_path(self, indicator: Indicator) -> str | None:
        if indicator.type in HASH_TYPES:
            return f"/files/{indicator.value}"
        if indicator.type is IndicatorType.URL:
            # VT URL endpoint uses base64url-encoded URL as the ID.
            url_id = base64.urlsafe_b64encode(indicator.value.encode()).rstrip(b"=")
            return f"/urls/{url_id.decode()}"
        collection = dict(COLLECTION_BY_TYPE).get(indicator.type)
        return f"/{collection}/{indicator.value}" if collection else None

    def fetch(self, indicator: Indicator) -> Evidence | None:
        path = self.api_path(indicator)
        if path is None:
            return None
        response = self._http.get(
            f"{BASE_URL}{path}",
            RequestOptions(
                headers={"x-apikey": self._token, "Accept": "application/json"},
                timeout=TIMEOUT_S,
            ),
        )
        if response.status_code != HTTPStatus.OK:
            return None
        attributes = response.json().get("data", {}).get("attributes", {})
        return self._evidence(indicator, attributes)

    def _evidence(
        self, indicator: Indicator, attributes: Mapping[str, Any]
    ) -> Evidence:
        stats = EngineStats.of(attributes.get("last_analysis_stats") or {})
        verdict = stats.verdict()
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=verdict.hint,
            confidence=verdict.confidence,
            summary=(
                f"VirusTotal: {stats.malicious} malicious + "
                f"{stats.suspicious} suspicious / {stats.total} engines"
            ),
            details=self._details(attributes),
        )

    def _details(self, attributes: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "stats": attributes.get("last_analysis_stats") or {},
            "reputation": attributes.get("reputation"),
            "names": (attributes.get("names") or [])[:LISTED_NAMES],
            "type_description": attributes.get("type_description"),
            "popular_threat_classification": attributes.get(
                "popular_threat_classification"
            ),
        }
