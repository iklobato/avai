"""CISA Known Exploited Vulnerabilities catalog.

No key. The full catalog is one JSON file; we fetch once per TTL and
membership-test. A hit means "this CVE is being actively exploited in
the wild" — strong malicious signal for any installed_apps with that
package.

https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from __future__ import annotations

from typing import Any, ClassVar

from avai.enrichers.base import Evidence, Indicator, IndicatorType, VerdictHint
from avai.enrichers.feed import FeedEnricher

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


class CisaKevEnricher(FeedEnricher):
    name = "cisa_kev"
    supports_types = frozenset({IndicatorType.CVE})
    requires_token: ClassVar[str | None] = None
    ttl_hours = 12
    rate_host = "www.cisa.gov"
    rate_per_second = 1.0
    feed_url = URL

    def index(self, body: Any) -> dict[str, dict[str, Any]]:
        return {
            entry.get("cveID", "").upper(): entry
            for entry in (body or {}).get("vulnerabilities") or []
            if entry.get("cveID")
        }

    def fetch(self, indicator: Indicator) -> Evidence | None:
        hit = self.entry(indicator.value.upper())
        if hit is None:
            return None
        product = hit.get("product") or "?"
        added = hit.get("dateAdded") or ""
        ransomware = hit.get("knownRansomwareCampaignUse") or "?"
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.MALICIOUS,
            confidence=MALICIOUS_CONFIDENCE,
            summary=(
                f"CISA KEV: actively exploited "
                f"product={product} added={added} ransomware={ransomware}"
            ),
            details={field: hit.get(field) for field in DETAIL_FIELDS},
        )
