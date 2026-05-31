"""GitHub Advisory Database — curated advisories with CVSS + fix versions.

Requires ``GITHUB_TOKEN`` (any GitHub PAT with public_repo read).
https://docs.github.com/en/rest/security-advisories/global-advisories
"""
from __future__ import annotations

import os
from typing import ClassVar, Optional

from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    VerdictHint,
)
from avai.enrichers.http import HttpClient

_URL = "https://api.github.com/advisories"


class GitHubAdvisoryEnricher(Enricher):
    name           = "github_advisory"
    supports_types = frozenset({IndicatorType.CVE})
    requires_token: ClassVar[Optional[str]] = "GITHUB_TOKEN"
    ttl_hours      = 24

    def __init__(self, http: Optional[HttpClient] = None):
        self._http = http or HttpClient()
        self._http.set_rate("api.github.com", 4.0)
        self._token = os.environ.get("GITHUB_TOKEN", "")

    def _fetch(self, indicator: Indicator) -> Optional[Evidence]:
        resp = self._http.get(
            _URL,
            params={"cve_id": indicator.value.upper()},
            headers={
                "Authorization":         f"Bearer {self._token}",
                "Accept":                "application/vnd.github+json",
                "X-GitHub-Api-Version":  "2022-11-28",
            },
        )
        if resp.status_code != 200:
            return None
        items = resp.json() or []
        if not items:
            return None
        first = items[0]
        severity = (first.get("severity") or "").lower()
        score = (first.get("cvss") or {}).get("score")
        if severity in {"critical"} or (score and score >= 9):
            hint, conf = VerdictHint.MALICIOUS, 0.9
        elif severity in {"high"} or (score and score >= 7):
            hint, conf = VerdictHint.SUSPICIOUS, 0.7
        else:
            hint, conf = VerdictHint.UNKNOWN, 0.4
        return Evidence(
            source       = self.name,
            indicator    = indicator,
            verdict_hint = hint,
            confidence   = conf,
            summary      = (f"GH Advisory: severity={severity} "
                            f"score={score} — {first.get('summary')!s:.80}"),
            details      = {k: first.get(k) for k in (
                "ghsa_id", "summary", "severity", "cvss",
                "vulnerabilities", "published_at",
            )},
        )
