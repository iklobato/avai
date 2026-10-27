"""Enrichers backed by a whole downloadable feed instead of a per-indicator
API: the feed is fetched once, indexed by indicator, and re-fetched when it
is older than the freshness window."""

from __future__ import annotations

import threading
import time
from abc import abstractmethod
from collections.abc import Mapping
from typing import Any, ClassVar, Generic, TypeVar

from avai.enrichers.base import Enricher
from avai.enrichers.http import HttpClient
from avai.enrichers.reply import ApiReply

ONE_HOUR_S = 60 * 60
NEVER_FETCHED = 0.0

FeedEntry = TypeVar("FeedEntry", bound=ApiReply)


class FeedEnricher(Enricher, Generic[FeedEntry]):
    feed_url: ClassVar[str]
    feed_fresh_s: ClassVar[float] = ONE_HOUR_S

    def __init__(self, http: HttpClient, lock: threading.Lock) -> None:
        self._http = http
        self._lock = lock
        self._index: dict[str, FeedEntry] = {}
        self._fetched_at = NEVER_FETCHED

    @classmethod
    def create(
        cls, http: HttpClient, env: Mapping[str, str]
    ) -> FeedEnricher[FeedEntry]:
        if cls.rate_host is not None:
            http.set_rate(cls.rate_host, cls.rate_per_second)
        return cls(http, threading.Lock())

    def entry(self, key: str) -> FeedEntry | None:
        self._refresh()
        return self._index.get(key)

    @abstractmethod
    def index(self, body: Any) -> dict[str, FeedEntry]:
        """The feed's entries keyed by the indicator value they describe."""

    def _refresh(self) -> None:
        now = time.monotonic()
        with self._lock:
            if self._index and (now - self._fetched_at) < self.feed_fresh_s:
                return
            response = self._http.get(self.feed_url)
            response.raise_for_status()
            self._index = self.index(response.json())
            self._fetched_at = now
