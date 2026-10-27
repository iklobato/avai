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
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from http import HTTPStatus
from typing import Any

import requests

from avai import __version__ as AVAI_VERSION
from avai.enrichers.base import EnricherError, RateLimitedError

USER_AGENT = f"avai-monitor/{AVAI_VERSION} (+https://github.com/iklobato/avai)"
DEFAULT_TIMEOUT_S = 8.0
DEFAULT_RATE_PER_SECOND = 4.0
MIN_RATE_PER_SECOND = 0.01
RETRY_STATUS = frozenset({500, 502, 503, 504})
RETRY_BACKOFFS_S = (0.4, 1.2, 3.0)
# Each backoff is jittered by ±25%: multiplied by a factor in [0.75, 1.25).
JITTER_FLOOR = 0.75
JITTER_SPAN = 0.5
# A 429's Retry-After up to this is waited out; a longer one gives up so
# the cycle doesn't stall.
MAX_RETRY_AFTER_S = 5
NO_WAIT_S = 0.0
# The bucket starts full: the first take() must never wait. ``0.0`` is
# wrong because ``time.monotonic()`` counts from an arbitrary epoch
# (system uptime on Linux) — on a low-uptime host where
# ``monotonic() < period`` the first call would sleep up to a full period
# (hours for a slow source). ``-inf`` makes the first wait unconditionally
# negative, then real pacing kicks in from take().
BUCKET_START = float("-inf")


class HttpMethod(StrEnum):
    GET = "GET"
    POST = "POST"


class RetriesExhaustedError(EnricherError):
    """Every attempt failed without a transport error to re-raise."""


@dataclass(frozen=True)
class RequestOptions:
    headers: Mapping[str, str] | None = None
    params: Mapping[str, Any] | None = None
    form_body: Any = None
    json: Any = None
    timeout: float = DEFAULT_TIMEOUT_S

    def as_kwargs(self) -> dict[str, Any]:
        sent = {
            "headers": self.headers,
            "params": self.params,
            "data": self.form_body,
            "json": self.json,
        }
        kwargs = {key: value for key, value in sent.items() if value is not None}
        kwargs["timeout"] = self.timeout
        return kwargs


@dataclass(frozen=True)
class HttpCall:
    method: HttpMethod
    url: str
    options: RequestOptions

    def __str__(self) -> str:
        return f"{self.method} {self.url}"

    @property
    def host(self) -> str:
        # Sufficient for rate limiting; not validating the URL.
        try:
            return self.url.split("://", 1)[1].split("/", 1)[0].lower()
        except IndexError:
            return self.url


class Waiter:
    """The time the client waits on: sleeps, a clock that never goes back
    and the backoff jitter. Tests pass a fake that records every wait."""

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def monotonic(self) -> float:
        return time.monotonic()

    def jitter(self) -> float:
        return random.random()


class TokenBucket:
    """Per-host rate limiter. Sleeps the calling thread to stay under
    the configured rate; never returns ``False``. Simple, intentionally
    coarse — we're targeting "don't get banned", not microsecond-level
    pacing."""

    def __init__(self, period_s: float, lock: threading.Lock, waiter: Waiter) -> None:
        self._period_s = period_s
        self._lock = lock
        self._waiter = waiter
        self._last = BUCKET_START

    @classmethod
    def for_rate(cls, rate_per_second: float, waiter: Waiter) -> TokenBucket:
        period_s = 1.0 / max(rate_per_second, MIN_RATE_PER_SECOND)
        return cls(period_s, threading.Lock(), waiter)

    def take(self) -> None:
        with self._lock:
            wait = (self._last + self._period_s) - self._waiter.monotonic()
            if wait > 0:
                self._waiter.sleep(wait)
            self._last = self._waiter.monotonic()


class HostRateLimits:
    """One token bucket per host, created on first use at the default rate."""

    def __init__(
        self, default_rate: float, lock: threading.Lock, waiter: Waiter
    ) -> None:
        self._default_rate = default_rate
        self._lock = lock
        self._waiter = waiter
        self._buckets: dict[str, TokenBucket] = {}

    def set_rate(self, host: str, rate_per_second: float) -> None:
        with self._lock:
            self._buckets[host] = TokenBucket.for_rate(rate_per_second, self._waiter)

    def bucket_for(self, host: str) -> TokenBucket:
        with self._lock:
            if host not in self._buckets:
                bucket = TokenBucket.for_rate(self._default_rate, self._waiter)
                self._buckets[host] = bucket
            return self._buckets[host]


class RetryAfter:
    """Reads a 429's Retry-After header as the seconds worth waiting out."""

    def __init__(self, response: requests.Response) -> None:
        self._response = response

    def wait_s(self) -> float:
        raw = self._response.headers.get("Retry-After")
        if not raw:
            return NO_WAIT_S
        try:
            return float(raw)
        except ValueError:
            return NO_WAIT_S

    def is_worth_waiting(self) -> bool:
        return 0 < self.wait_s() <= MAX_RETRY_AFTER_S


@dataclass(frozen=True)
class HttpPacing:
    """How fast the client may call each host and how it waits."""

    rates: HostRateLimits
    waiter: Waiter


class SessionTransport:
    """Sends one call through a requests session. Tests pass a fake that
    hands out canned replies."""

    def __init__(self, session: requests.Session) -> None:
        self._session = session

    @classmethod
    def identified(cls) -> SessionTransport:
        return cls(cls.identified_session())

    @classmethod
    def identified_session(cls) -> requests.Session:
        """A session that names avai in its User-Agent."""
        session = requests.Session()
        session.headers["User-Agent"] = USER_AGENT
        return session

    def send(self, call: HttpCall) -> requests.Response:
        return self._session.request(call.method, call.url, **call.options.as_kwargs())


class HttpClient:
    """One per process. Pass to enrichers via constructor; never
    instantiate per-call."""

    def __init__(
        self,
        transport: SessionTransport,
        pacing: HttpPacing,
        logger: logging.Logger,
    ) -> None:
        self._transport = transport
        self._pacing = pacing
        self._logger = logger

    @classmethod
    def create(
        cls, logger: logging.Logger, default_rate: float = DEFAULT_RATE_PER_SECOND
    ) -> HttpClient:
        waiter = Waiter()
        rates = HostRateLimits(default_rate, threading.Lock(), waiter)
        return cls(SessionTransport.identified(), HttpPacing(rates, waiter), logger)

    def set_rate(self, host: str, rate_per_second: float) -> None:
        """Override the per-host rate (call once at registry time)."""
        self._pacing.rates.set_rate(host, rate_per_second)

    def get(self, url: str, options: RequestOptions | None = None) -> requests.Response:
        return self._request(HttpMethod.GET, url, options or RequestOptions())

    def post(
        self, url: str, options: RequestOptions | None = None
    ) -> requests.Response:
        return self._request(HttpMethod.POST, url, options or RequestOptions())

    def _request(
        self, method: HttpMethod, url: str, options: RequestOptions
    ) -> requests.Response:
        call = HttpCall(method, url, options)
        bucket = self._pacing.rates.bucket_for(call.host)
        last_error: requests.RequestException | None = None
        for attempt, backoff in enumerate((NO_WAIT_S, *RETRY_BACKOFFS_S)):
            self._sleep_jittered(backoff)
            bucket.take()
            try:
                return self._attempt(call, attempt)
            except requests.RequestException as exc:
                last_error = exc
                self._logger.debug(
                    "http %s attempt %d failed: %s", call, attempt + 1, exc
                )
        raise last_error or RetriesExhaustedError(f"http {call} exhausted retries")

    def _attempt(self, call: HttpCall, attempt: int) -> requests.Response:
        """One request; raises ``HTTPError`` on a status worth retrying."""
        response = self._transport.send(call)
        if self._should_retry_rate_limit(response, call.host, attempt):
            raise requests.HTTPError(f"{response.status_code} from {call.host}")
        if response.status_code in RETRY_STATUS:
            raise requests.HTTPError(f"{response.status_code} from {call.host}")
        return response

    def _sleep_jittered(self, backoff: float) -> None:
        if backoff:
            factor = JITTER_FLOOR + self._pacing.waiter.jitter() * JITTER_SPAN
            self._pacing.waiter.sleep(backoff * factor)

    def _should_retry_rate_limit(
        self, response: requests.Response, host: str, attempt: int
    ) -> bool:
        """True when a small Retry-After was waited out; raises on a 429
        that is not worth waiting for."""
        if response.status_code != HTTPStatus.TOO_MANY_REQUESTS:
            return False
        retry_after = RetryAfter(response)
        if retry_after.is_worth_waiting() and attempt < len(RETRY_BACKOFFS_S):
            self._pacing.waiter.sleep(retry_after.wait_s())
            return True
        raise RateLimitedError(f"{host} returned 429")
