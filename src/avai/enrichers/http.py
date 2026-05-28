"""Shared HTTP client for all enrichers.

One ``requests.Session`` with pooled connections, sensible default
timeout, per-host token-bucket rate limit, retry with exponential
backoff + jitter on transient errors, and 429-handling that surfaces
as :class:`RateLimitedError`.

Decoupled from any one source so every enricher can call the same
``client.get(...)`` / ``client.post(...)`` and the framework owns
the politeness rules.
"""
from __future__ import annotations

import logging
import random
import threading
import time
from collections import defaultdict
from typing import Any, Mapping, Optional

import requests

from avai.enrichers.base import RateLimitedError

LOG = logging.getLogger("avai.enrichers.http")

_USER_AGENT = "avai-monitor/0.1 (+https://github.com/iklobato/avai)"
_DEFAULT_TIMEOUT = 8.0
_RETRY_STATUS    = (500, 502, 503, 504)
_RETRY_BACKOFFS  = (0.4, 1.2, 3.0)  # seconds, jittered ±25%


class _TokenBucket:
    """Per-host rate limiter. Sleeps the calling thread to stay under
    the configured rate; never returns ``False``. Simple, intentionally
    coarse — we're targeting "don't get banned", not microsecond-level
    pacing."""

    def __init__(self, rate_per_second: float):
        self._period = 1.0 / max(rate_per_second, 0.01)
        self._last   = 0.0
        self._lock   = threading.Lock()

    def take(self) -> None:
        with self._lock:
            wait = (self._last + self._period) - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()


class HttpClient:
    """One per process. Pass to enrichers via constructor; never
    instantiate per-call."""

    def __init__(self, default_rate: float = 4.0):
        self._session = requests.Session()
        self._session.headers["User-Agent"] = _USER_AGENT
        self._buckets: dict[str, _TokenBucket] = defaultdict(
            lambda: _TokenBucket(default_rate)
        )
        self._bucket_lock = threading.Lock()

    def set_rate(self, host: str, rate_per_second: float) -> None:
        """Override the per-host rate (call once at registry time)."""
        with self._bucket_lock:
            self._buckets[host] = _TokenBucket(rate_per_second)

    # -- public verbs -----------------------------------------------------

    def get(self, url: str, *,
            headers: Optional[Mapping[str, str]] = None,
            params: Optional[Mapping[str, Any]] = None,
            timeout: float = _DEFAULT_TIMEOUT) -> requests.Response:
        return self._request("GET", url, headers=headers, params=params,
                             timeout=timeout)

    def post(self, url: str, *,
             headers: Optional[Mapping[str, str]] = None,
             data: Optional[Any] = None,
             json: Optional[Any] = None,
             timeout: float = _DEFAULT_TIMEOUT) -> requests.Response:
        return self._request("POST", url, headers=headers, data=data,
                             json=json, timeout=timeout)

    # -- internals --------------------------------------------------------

    def _host_of(self, url: str) -> str:
        # Sufficient for rate limiting; not validating the URL.
        try:
            return url.split("://", 1)[1].split("/", 1)[0].lower()
        except IndexError:
            return url

    def _request(self, method: str, url: str, **kw) -> requests.Response:
        host = self._host_of(url)
        bucket = self._buckets[host]
        last_exc: Optional[BaseException] = None

        for attempt, backoff in enumerate((0.0, *_RETRY_BACKOFFS)):
            if backoff:
                jitter = backoff * (0.75 + random.random() * 0.5)
                time.sleep(jitter)
            bucket.take()
            try:
                resp = self._session.request(method, url, **kw)
            except requests.RequestException as exc:
                last_exc = exc
                LOG.debug("http %s %s attempt %d failed: %s",
                          method, url, attempt + 1, exc)
                continue
            if resp.status_code == 429:
                # 429 with Retry-After: respect a small one, give up on
                # large ones so the cycle doesn't stall.
                retry_after = resp.headers.get("Retry-After")
                try:
                    wait_s = float(retry_after) if retry_after else 0
                except ValueError:
                    wait_s = 0
                if 0 < wait_s <= 5 and attempt < len(_RETRY_BACKOFFS):
                    time.sleep(wait_s)
                    continue
                raise RateLimitedError(f"{host} returned 429")
            if resp.status_code in _RETRY_STATUS:
                last_exc = requests.HTTPError(
                    f"{resp.status_code} from {host}")
                continue
            return resp

        if last_exc is not None:
            raise last_exc  # noqa: TRY201
        raise RuntimeError(f"http {method} {url} exhausted retries")
