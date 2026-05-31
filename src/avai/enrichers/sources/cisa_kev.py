"""CISA Known Exploited Vulnerabilities catalog.

No key. The full catalog is one JSON file; we fetch once per TTL and
membership-test. A hit means "this CVE is being actively exploited in
the wild" — strong malicious signal for any installed_apps with that
package.

https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""
from __future__ import annotations

import threading
import time
from typing import ClassVar, Optional

from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    VerdictHint,
)
from avai.enrichers.http import HttpClient

_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaKevEnricher(Enricher):
    name           = "cisa_kev"
    supports_types = frozenset({IndicatorType.CVE})
    requires_token: ClassVar[Optional[str]] = None
    ttl_hours      = 12

    _catalog: dict[str, dict] = {}
    _catalog_ts: float = 0.0
    _lock = threading.Lock()
    _FEED_FRESH_SECS = 60 * 60

    def __init__(self, http: Optional[HttpClient] = None):
        self._http = http or HttpClient()
        self._http.set_rate("www.cisa.gov", 1.0)

    def _ensure_catalog(self) -> None:
        now = time.monotonic()
        with self._lock:
            if self._catalog and (now - self._catalog_ts) < self._FEED_FRESH_SECS:
                return
            resp = self._http.get(_URL)
            resp.raise_for_status()
            body = resp.json() or {}
            CisaKevEnricher._catalog = {
                v.get("cveID", "").upper(): v
                for v in body.get("vulnerabilities") or []
                if v.get("cveID")
            }
            CisaKevEnricher._catalog_ts = now

    def _fetch(self, indicator: Indicator) -> Optional[Evidence]:
        self._ensure_catalog()
        hit = self._catalog.get(indicator.value.upper())
        if hit is None:
            return None
        product = hit.get("product") or "?"
        added   = hit.get("dateAdded") or ""
        ransom  = hit.get("knownRansomwareCampaignUse") or "?"
        return Evidence(
            source       = self.name,
            indicator    = indicator,
            verdict_hint = VerdictHint.MALICIOUS,
            confidence   = 0.98,
            summary      = (f"CISA KEV: actively exploited "
                            f"product={product} added={added} ransomware={ransom}"),
            details      = {k: hit.get(k) for k in (
                "product", "vendorProject", "vulnerabilityName",
                "dateAdded", "shortDescription", "requiredAction",
                "knownRansomwareCampaignUse",
            )},
        )
