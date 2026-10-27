"""abuse.ch Feodo Tracker — known botnet C2 IP feed.

No key. The feed is a static JSON list; we fetch once per ttl and
membership-test against it. Cheap, no per-IP API call.

https://feodotracker.abuse.ch/downloads/ipblocklist.json
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import TypeAdapter

from avai.enrichers.base import Evidence, Indicator, IndicatorType, VerdictHint
from avai.enrichers.feed import FeedEnricher
from avai.enrichers.reply import ApiReply

URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
MALICIOUS_CONFIDENCE = 0.97
DETAIL_FIELDS = (
    "malware",
    "port",
    "first_seen",
    "last_online",
    "as_number",
    "as_name",
    "country",
)


class FeodoEntry(ApiReply):
    """One botnet C2 address."""

    ip_address: object = ""
    malware: object = None


class FeodoTrackerEnricher(FeedEnricher[FeodoEntry]):
    name = "feodo_tracker"
    supports_types = frozenset({IndicatorType.IPV4})
    requires_token: ClassVar[str | None] = None
    ttl_hours = 6  # the feed itself is refreshed hourly
    rate_host = "feodotracker.abuse.ch"
    rate_per_second = 1.0
    feed_url = URL

    def index(self, body: Any) -> dict[str, FeodoEntry]:
        entries = TypeAdapter(list[FeodoEntry]).validate_python(body or [])
        return {
            entry.ip_address.strip(): entry
            for entry in entries
            if entry.ip_address
        }

    def fetch(self, indicator: Indicator) -> Evidence | None:
        hit = self.entry(indicator.value)
        if hit is None:
            return None
        family = hit.malware or "?"
        return Evidence(
            source=self.name,
            indicator=indicator,
            verdict_hint=VerdictHint.MALICIOUS,
            confidence=MALICIOUS_CONFIDENCE,
            summary=f"Feodo Tracker: known botnet C2 (malware={family})",
            details=hit.given(DETAIL_FIELDS),
        )
