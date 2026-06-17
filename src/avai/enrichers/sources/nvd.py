"""NIST NVD — CVE detail lookup (description + CVSS).

Optional API key (``NVD_API_KEY``) ups the rate limit from 5 req / 30 s
to 50 req / 30 s.
https://nvd.nist.gov/developers/vulnerabilities
"""
from __future__ import annotations

import os
from typing import ClassVar, Optional

from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    RateLimitedError,
    VerdictHint,
)
from avai.enrichers.http import HttpClient

_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdEnricher(Enricher):
    name           = "nvd"
    supports_types = frozenset({IndicatorType.CVE})
    # No required token — but if NVD_API_KEY is set we send it.
    requires_token: ClassVar[Optional[str]] = None
    ttl_hours      = 24 * 7

    def __init__(self, http: Optional[HttpClient] = None):
        self._http = http or HttpClient()
        # Slow lane without a key; bump if the user supplied one.
        rate = 1.5 if os.environ.get("NVD_API_KEY") else 0.15
        self._http.set_rate("services.nvd.nist.gov", rate)

    def _fetch(self, indicator: Indicator) -> Optional[Evidence]:
        headers = {}
        key = os.environ.get("NVD_API_KEY")
        if key:
            headers["apiKey"] = key
        resp = self._http.get(
            _URL,
            params={"cveId": indicator.value.upper()},
            headers=headers,
            timeout=10.0,
        )
        # NVD returns 403 when the (keyless) rate window is exceeded; treat
        # it as a rate-limit so the chain backs off rather than recording a
        # silent "no opinion" on every CVE under load.
        if resp.status_code == 403:
            raise RateLimitedError("nvd returned 403 (rate limited / over quota)")
        if resp.status_code != 200:
            return None
        vulns = (resp.json().get("vulnerabilities") or [])
        if not vulns:
            return None
        cve = vulns[0].get("cve") or {}
        metrics = cve.get("metrics") or {}
        cvss31 = (metrics.get("cvssMetricV31") or [{}])[0].get("cvssData") or {}
        score  = cvss31.get("baseScore")
        sev    = cvss31.get("baseSeverity") or "?"
        desc   = next(
            (d.get("value") for d in cve.get("descriptions", [])
             if d.get("lang") == "en"),
            "",
        )[:200]
        hint = (VerdictHint.MALICIOUS if score and score >= 9
                else VerdictHint.SUSPICIOUS if score and score >= 7
                else VerdictHint.UNKNOWN)
        return Evidence(
            source       = self.name,
            indicator    = indicator,
            verdict_hint = hint,
            confidence   = 0.7,
            summary      = f"NVD: CVSS={score} {sev} — {desc}",
            details      = {"cvss31": cvss31, "description": desc,
                            "published": cve.get("published"),
                            "modified": cve.get("lastModified")},
        )
