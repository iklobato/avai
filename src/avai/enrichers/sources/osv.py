"""OSV.dev — open-source vulnerability database.

No key. Free. Queries by package name+version (PyPI, npm, Go, etc.)
or by ecosystem CVE.

https://osv.dev/docs/
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Any, ClassVar

from pydantic import field_validator

from avai.enrichers.reply import ApiReply
from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    VerdictHint,
)
from avai.enrichers.http import RequestOptions

QUERY_URL = "https://api.osv.dev/v1/query"
VULN_URL = "https://api.osv.dev/v1/vulns"
# Only the first few advisories are listed in the evidence.
MAX_LISTED_VULNS = 5
ADVISORY_CONFIDENCE = 0.75
PYPI_NAMES = frozenset({"pip", "python"})


class OsvVuln(ApiReply):
    """One OSV vulnerability record."""

    id: object = None
    aliases: object = None
    summary: object = None


class OsvQueryReply(ApiReply):
    vulns: list[OsvVuln] = []

    @field_validator("vulns", mode="before")
    @classmethod
    def _present(cls, value: Any) -> Any:
        return value or []


class OSVEnricher(Enricher):
    name = "osv"
    supports_types = frozenset({IndicatorType.PACKAGE, IndicatorType.CVE})
    requires_token: ClassVar[str | None] = None
    ttl_hours = 24
    rate_host = "api.osv.dev"
    rate_per_second = 4.0

    def fetch(self, indicator: Indicator) -> Evidence | None:
        if indicator.type is IndicatorType.CVE:
            vulns = self._vuln_by_id(indicator.value)
        else:
            vulns = self._vulns_for_package(indicator.value)
        if not vulns:
            return None
        return self._evidence(indicator, vulns)

    def _evidence(self, indicator: Indicator, vulns: list[OsvVuln]) -> Evidence:
        listed = vulns[:MAX_LISTED_VULNS]
        ids = self.advisory_ids(listed)
        # Treat severity-tagged vulns as suspicious. Without severity
        # data we still report — better signal than silence.
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.SUSPICIOUS,
            confidence=ADVISORY_CONFIDENCE,
            summary=f"OSV: {len(vulns)} advisory hit(s): {','.join(ids)}",
            details={
                "vuln_ids": ids,
                "summaries": [vuln.summary for vuln in listed],
            },
        )

    def advisory_ids(self, vulns: list[OsvVuln]) -> list[str]:
        """Each vuln's primary id AND its aliases, deduplicated. OSV's primary
        id is often a GHSA-/PYSEC-/OSV- id with the CVE only in aliases; the
        chain forward-enriches CVE-/GHSA- ids (CVSS, KEV), so a CVE buried in
        aliases must be surfaced or that stage never runs."""
        ids = (
            candidate
            for vuln in vulns
            for candidate in (vuln.id, *(vuln.aliases or []))
        )
        return list(dict.fromkeys(candidate for candidate in ids if candidate))

    def ecosystem_for(self, package_name: str) -> str:
        """Heuristic ecosystem mapping. avai's `installed_apps` collector
        doesn't yet record ecosystem, so we try a sensible default; an empty
        ecosystem makes OSV do a global search."""
        lowered = package_name.lower()
        if lowered.endswith(".pyz") or lowered in PYPI_NAMES:
            return "PyPI"
        return ""

    def _vuln_by_id(self, vuln_id: str) -> list[OsvVuln]:
        # id lookups use GET /v1/vulns/{id}; POST /v1/query rejects a
        # top-level {"id": ...} with HTTP 400 (verified against the API).
        response = self._http.get(f"{VULN_URL}/{vuln_id.upper()}")
        if response.status_code != HTTPStatus.OK:
            return []
        return [OsvVuln.model_validate(response.json())]

    def _vulns_for_package(self, package: str) -> list[OsvVuln]:
        # PACKAGE is "<name>@<version>". Either piece may be missing.
        package_name, _, version = package.partition("@")
        if not package_name:
            return []
        response = self._http.post(
            QUERY_URL, RequestOptions(json=self._query(package_name, version))
        )
        if response.status_code != HTTPStatus.OK:
            return []
        return OsvQueryReply.model_validate(response.json()).vulns

    def _query(self, package_name: str, version: str) -> dict[str, Any]:
        package_spec = {"name": package_name}
        ecosystem = self.ecosystem_for(package_name)
        if ecosystem:
            package_spec["ecosystem"] = ecosystem
        query: dict[str, Any] = {"package": package_spec}
        if version:
            query["version"] = version
        return query
