"""abuse.ch URLhaus — malware-distribution URLs and domains.

Requires ``ABUSE_CH_AUTH_KEY`` (free; same key as MalwareBazaar +
ThreatFox). Register at https://auth.abuse.ch/.
https://urlhaus-api.abuse.ch/
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

URL_LOOKUP = "https://urlhaus-api.abuse.ch/v1/url/"
HOST_LOOKUP = "https://urlhaus-api.abuse.ch/v1/host/"
NO_URLS = 0
URL_CONFIDENCE = 0.9
HOST_CONFIDENCE = 0.7
URL_DETAIL_FIELDS = (
    "threat",
    "url_status",
    "tags",
    "date_added",
    "blacklists",
    "payloads",
)
HOST_DETAIL_FIELDS = ("firstseen", "url_count", "blacklists", "urlhaus_reference")


class UrlhausReply(ApiReply):
    """A /url/ or /host/ lookup; the two share only ``query_status``."""

    query_status: object = None
    threat: object = None
    tags: object = None
    url_status: object = None
    date_added: object = None
    firstseen: object = None
    url_count: int = NO_URLS

    @field_validator("url_count", mode="before")
    @classmethod
    def _url_count(cls, value: Any) -> int:
        """A missing or non-numeric count means no URLs."""
        try:
            return int(value or NO_URLS)
        except (TypeError, ValueError):
            return NO_URLS


class URLhausEnricher(Enricher):
    name = "urlhaus"
    supports_types = frozenset({IndicatorType.URL, IndicatorType.DOMAIN})
    requires_token: ClassVar[str | None] = "ABUSE_CH_AUTH_KEY"
    ttl_hours = 12
    rate_host = "urlhaus-api.abuse.ch"
    rate_per_second = 2.0

    def fetch(self, indicator: Indicator) -> Evidence | None:
        is_url = indicator.type is IndicatorType.URL
        endpoint, field = (URL_LOOKUP, "url") if is_url else (HOST_LOOKUP, "host")
        response = self._http.post(
            endpoint,
            RequestOptions(
                form_body={field: indicator.value}, headers={"Auth-Key": self._token}
            ),
        )
        if response.status_code != HTTPStatus.OK:
            return None
        body = UrlhausReply.model_validate(response.json())
        if body.query_status != "ok":
            return None
        # The /url/ and /host/ responses have different shapes: a URL hit
        # carries threat/url_status/tags/date_added; a host hit carries
        # firstseen/url_count/urls[] with NO top-level threat. Parse each.
        if is_url:
            return self._url_evidence(indicator, body)
        return self._host_evidence(indicator, body)

    def _url_evidence(self, indicator: Indicator, body: UrlhausReply) -> Evidence:
        threat = body.threat or "?"
        tags = body.tags or []
        status = body.url_status or "?"
        added = body.date_added or ""
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.MALICIOUS,
            confidence=URL_CONFIDENCE,
            summary=(
                f"URLhaus: known-malicious url, threat={threat} status={status} "
                f"tags={tags} added={added}"
            ),
            details=body.given(URL_DETAIL_FIELDS),
        )

    def _host_evidence(
        self, indicator: Indicator, body: UrlhausReply
    ) -> Evidence | None:
        # host/domain: "ok" only means URLhaus knows the host; a host with
        # zero associated malware URLs is not actionable.
        url_count = body.url_count
        if url_count <= NO_URLS:
            return None
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.SUSPICIOUS,
            confidence=HOST_CONFIDENCE,
            summary=(
                f"URLhaus: host has hosted {url_count} malware URL(s), "
                f"firstseen={body.firstseen or ''}"
            ),
            details=body.given(HOST_DETAIL_FIELDS),
        )
