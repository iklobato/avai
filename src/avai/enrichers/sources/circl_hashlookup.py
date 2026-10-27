"""CIRCL hashlookup — NSRL "known-good" filter.

No key. Free. The NSRL is the National Software Reference Library's
hash database of legitimate vendor binaries. A hit here is a strong
*benign* signal — useful for whitelisting OS-shipped binaries that
would otherwise burn judge tokens.

https://hashlookup.circl.lu/
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from avai.enrichers.base import (
    Enricher,
    Evidence,
    Indicator,
    IndicatorType,
    VerdictHint,
)
from avai.enrichers.http import RequestOptions

BASE_URL = "https://hashlookup.circl.lu/lookup"
# CIRCL scores each hash 0-100 in "hashlookup:trust". Only a high score
# is a genuine known-good signal; below this we give no opinion rather
# than a false benign that could suppress the judge.
MIN_TRUST = 50
NO_TRUST = 0
BENIGN_CONFIDENCE = 0.9
TWO_WEEKS_HOURS = 24 * 14
DETAIL_FIELDS = (
    "FileName",
    "FileSize",
    "ProductCode",
    "OpSystemCode",
    "source",
    "hashlookup:trust",
    "hashlookup:parent-total",
)


class CirclRecord(BaseModel):
    """A hashlookup hit; fields other than the ones read stay as given."""

    model_config = ConfigDict(frozen=True, extra="allow", populate_by_name=True)

    trust: int = Field(NO_TRUST, alias="hashlookup:trust")
    file_name: str | None = Field(None, alias="FileName")
    product_code: str | None = Field(None, alias="ProductCode")

    @field_validator("trust", mode="before")
    @classmethod
    def _trust(cls, value: Any) -> int:
        """A missing or non-numeric score counts as no trust."""
        try:
            return int(value)
        except (TypeError, ValueError):
            return NO_TRUST

    def label(self) -> str:
        return self.file_name or self.product_code or "?"

    def details(self) -> dict[str, Any]:
        given = self.model_dump(by_alias=True)
        return {field: given.get(field) for field in DETAIL_FIELDS}


class CirclHashlookupEnricher(Enricher):
    name = "circl_hashlookup"
    supports_types = frozenset(
        {IndicatorType.SHA256, IndicatorType.SHA1, IndicatorType.MD5}
    )
    requires_token: ClassVar[str | None] = None
    ttl_hours = TWO_WEEKS_HOURS  # NSRL is slow-moving; cache long.
    rate_host = "hashlookup.circl.lu"
    rate_per_second = 4.0

    def fetch(self, indicator: Indicator) -> Evidence | None:
        response = self._http.get(
            f"{BASE_URL}/{indicator.type}/{indicator.value}",
            RequestOptions(headers={"Accept": "application/json"}),
        )
        if response.status_code != HTTPStatus.OK:
            return None
        record = CirclRecord.model_validate(response.json())
        # Low-trust hashes are known to CIRCL but seen in untrusted/malicious
        # contexts — not a whitelist hit. Give no opinion rather than benign.
        if record.trust < MIN_TRUST:
            return None
        return self._evidence(indicator, record)

    def _evidence(self, indicator: Indicator, record: CirclRecord) -> Evidence:
        # Real CIRCL fields (verified against the live API): FileName,
        # FileSize, ProductCode, OpSystemCode, source, and the trust score
        # "hashlookup:trust" (0-100). There is no ProductName/KnownMalicious.
        trust = record.trust
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.BENIGN,
            confidence=BENIGN_CONFIDENCE,
            summary=f"CIRCL/NSRL: known-good binary ({record.label()}, trust={trust})",
            details=record.details(),
        )
