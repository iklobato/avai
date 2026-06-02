"""OSV.dev — open-source vulnerability database.

No key. Free. Queries by package name+version (PyPI, npm, Go, etc.)
or by ecosystem CVE.

https://osv.dev/docs/
"""
from __future__ import annotations

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
            payload = {"id": indicator.value.upper()}
        else:
            # PACKAGE is "<name>@<version>". Either piece may be missing.
            name, _, version = indicator.value.partition("@")
            if not name:
                return None
            pkg = {"name": name}
            ecosystem = _ecosystem_for(name)
            if ecosystem:
                pkg["ecosystem"] = ecosystem
            payload = {"package": pkg}
            if version:
                payload["version"] = version
        resp = self._http.post(_QUERY, json=payload)
        if resp.status_code != 200:
            return None
        body = resp.json()
        vulns = body.get("vulns") or []
        if not vulns:
            return None
        # Collect each vuln's primary id AND its aliases. OSV's primary
        # id is often a GHSA-/PYSEC-/OSV- id with the CVE only in aliases;
        # the chain forward-enriches CVE-/GHSA- ids (CVSS, KEV), so a
        # CVE buried in aliases must be surfaced or that stage never runs.
        seen: set[str] = set()
        ids: list[str] = []
        for v in vulns[:5]:
            for cand in (v.get("id"), *(v.get("aliases") or [])):
                if cand and cand not in seen:
                    seen.add(cand)
                    ids.append(cand)
        # Treat severity-tagged vulns as suspicious. Without severity
        # data we still report — better signal than silence.
        return Evidence(
            source       = self.name,
            indicator    = indicator,
            verdict_hint = VerdictHint.SUSPICIOUS,
            confidence   = 0.75,
            summary      = f"OSV: {len(vulns)} advisory hit(s): {','.join(ids)}",
            details      = {"vuln_ids": ids,
                            "summaries": [v.get("summary") for v in vulns[:5]]},
        )
