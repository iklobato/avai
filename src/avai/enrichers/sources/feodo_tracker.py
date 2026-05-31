"""abuse.ch Feodo Tracker — known botnet C2 IP feed.

No key. The feed is a static JSON list; we fetch once per ttl and
membership-test against it. Cheap, no per-IP API call.

https://feodotracker.abuse.ch/downloads/ipblocklist.json
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

_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


class FeodoTrackerEnricher(Enricher):
    name           = "feodo_tracker"
    supports_types = frozenset({IndicatorType.IPV4})
    requires_token: ClassVar[Optional[str]] = None
    ttl_hours      = 6   # the feed itself is refreshed hourly

    # Cached feed shared across instances (still rare to construct
    # more than one in a process).
    _feed: dict[str, dict] = {}
    _feed_ts: float = 0.0
    _feed_lock = threading.Lock()
    _FEED_FRESH_SECS = 60 * 60

    def __init__(self, http: Optional[HttpClient] = None):
        self._http = http or HttpClient()
        self._http.set_rate("feodotracker.abuse.ch", 1.0)

    def _ensure_feed(self) -> None:
        now = time.monotonic()
        with self._feed_lock:
            if self._feed and (now - self._feed_ts) < self._FEED_FRESH_SECS:
                return
            resp = self._http.get(_URL)
            resp.raise_for_status()
            entries = resp.json() or []
            FeodoTrackerEnricher._feed = {
                e.get("ip_address", "").strip(): e
                for e in entries if e.get("ip_address")
            }
            FeodoTrackerEnricher._feed_ts = now

    def _fetch(self, indicator: Indicator) -> Optional[Evidence]:
        self._ensure_feed()
        hit = self._feed.get(indicator.value)
        if hit is None:
            return None
        family = hit.get("malware") or "?"
        return Evidence(
            source       = self.name,
            indicator    = indicator,
            verdict_hint = VerdictHint.MALICIOUS,
            confidence   = 0.97,
            summary      = f"Feodo Tracker: known botnet C2 (malware={family})",
            details      = {k: hit.get(k) for k in (
                "malware", "port", "first_seen", "last_online",
                "as_number", "as_name", "country",
            )},
        )
