"""CISA Known Exploited Vulnerabilities catalog.

No key. The full catalog is one JSON file; we fetch once per TTL and
membership-test. A hit means "this CVE is being actively exploited in
the wild" — strong malicious signal for any installed_apps with that
package.

https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import Field, field_validator

from avai.enrichers.base import Evidence, Indicator, IndicatorType, VerdictHint
from avai.enrichers.feed import FeedEnricher
from avai.enrichers.reply import ApiReply

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MALICIOUS_CONFIDENCE = 0.98
DETAIL_FIELDS = (
    "product",
    "vendorProject",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "knownRansomwareCampaignUse",
)


class KevEntry(ApiReply):
    """One known-exploited vulnerability."""

    cve_id: object = Field("", alias="cveID")
    product: object = None
    date_added: object = Field(None, alias="dateAdded")
    ransomware: object = Field(None, alias="knownRansomwareCampaignUse")


class KevFeed(ApiReply):
    vulnerabilities: list[KevEntry] = []

    @field_validator("vulnerabilities", mode="before")
    @classmethod
    def _present(cls, value: Any) -> Any:
        return value or []


class CisaKevEnricher(FeedEnricher[KevEntry]):
    name = "cisa_kev"
    supports_types = frozenset({IndicatorType.CVE})
    requires_token: ClassVar[str | None] = None
    ttl_hours = 12
    rate_host = "www.cisa.gov"
    rate_per_second = 1.0
    feed_url = URL

    def index(self, body: Any) -> dict[str, KevEntry]:
        feed = KevFeed.model_validate(body or {})
        return {
            entry.cve_id.upper(): entry
            for entry in feed.vulnerabilities
            if entry.cve_id
        }

    def fetch(self, indicator: Indicator) -> Evidence | None:
        hit = self.entry(indicator.value.upper())
        if hit is None:
            return None
        product = hit.product or "?"
        added = hit.date_added or ""
        ransomware = hit.ransomware or "?"
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.MALICIOUS,
            confidence=MALICIOUS_CONFIDENCE,
            summary=(
                f"CISA KEV: actively exploited "
                f"product={product} added={added} ransomware={ransomware}"
            ),
            details=hit.given(DETAIL_FIELDS),
        )
