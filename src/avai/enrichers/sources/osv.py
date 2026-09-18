"""OSV.dev — open-source vulnerability database.

No key. Free. Queries by package name+version (PyPI, npm, Go, etc.)
or by ecosystem CVE.

https://osv.dev/docs/
"""
from __future__ import annotations

from http import HTTPStatus
from typing import ClassVar, Optional

from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    VerdictHint,
)
from avai.enrichers.http import HttpClient

_QUERY = "https://api.osv.dev/v1/query"
_VULN = "https://api.osv.dev/v1/vulns"
# Only the first few advisories are listed in the evidence.
_MAX_LISTED_VULNS = 5


# Heuristic ecosystem mapping. avai's `installed_apps` collector
# doesn't yet record ecosystem, so we try a sensible default.
def _ecosystem_for(name: str) -> str:
    n = name.lower()
    if n.endswith(".pyz") or n in {"pip", "python"}:
        return "PyPI"
    return ""  # unknown ecosystem → OSV does a global search


class OSVEnricher(Enricher):
    name           = "osv"
    supports_types = frozenset({IndicatorType.PACKAGE, IndicatorType.CVE})
    requires_token: ClassVar[Optional[str]] = None
    ttl_hours      = 24

    def __init__(self, http: Optional[HttpClient] = None):
        self._http = http or HttpClient()
        self._http.set_rate("api.osv.dev", 4.0)

    def _fetch(self, indicator: Indicator) -> Optional[Evidence]:
        if indicator.type is IndicatorType.CVE:
            vulns = self._vuln_by_id(indicator.value)
        else:
            vulns = self._vulns_for_package(indicator.value)
        if not vulns:
            return None
        listed = vulns[:_MAX_LISTED_VULNS]
        ids = _advisory_ids(listed)
        # Treat severity-tagged vulns as suspicious. Without severity
        # data we still report — better signal than silence.
        return Evidence(
            source       = self.name,
            indicator    = indicator,
            verdict_hint = VerdictHint.SUSPICIOUS,
            confidence   = 0.75,
            summary      = f"OSV: {len(vulns)} advisory hit(s): {','.join(ids)}",
            details      = {"vuln_ids": ids,
                            "summaries": [v.get("summary") for v in listed]},
        )

    def _vuln_by_id(self, vuln_id: str) -> list[dict]:
        # id lookups use GET /v1/vulns/{id}; POST /v1/query rejects a
        # top-level {"id": ...} with HTTP 400 (verified against the API).
        resp = self._http.get(f"{_VULN}/{vuln_id.upper()}")
        if resp.status_code != HTTPStatus.OK:
            return []
        return [resp.json()]

    def _vulns_for_package(self, package: str) -> list[dict]:
        # PACKAGE is "<name>@<version>". Either piece may be missing.
        name, _, version = package.partition("@")
        if not name:
            return []
        pkg = {"name": name}
        ecosystem = _ecosystem_for(name)
        if ecosystem:
            pkg["ecosystem"] = ecosystem
        payload = {"package": pkg}
        if version:
            payload["version"] = version
        resp = self._http.post(_QUERY, json=payload)
        if resp.status_code != HTTPStatus.OK:
            return []
        return resp.json().get("vulns") or []


def _advisory_ids(vulns: list[dict]) -> list[str]:
    """Each vuln's primary id AND its aliases, deduplicated. OSV's primary
    id is often a GHSA-/PYSEC-/OSV- id with the CVE only in aliases; the
    chain forward-enriches CVE-/GHSA- ids (CVSS, KEV), so a CVE buried in
    aliases must be surfaced or that stage never runs."""
    ids = (cand for v in vulns for cand in (v.get("id"), *(v.get("aliases") or [])))
    return list(dict.fromkeys(cand for cand in ids if cand))
