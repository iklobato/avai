"""Tests for the shared HttpClient.

Locks down the parts of HTTP behaviour the enrichers depend on:
host parsing, per-host rate limiting, exponential backoff on
transient errors, 429 handling with and without Retry-After, and
exhaustion of the retry budget.

Network-free and sleep-free: the client gets a fake transport that hands
out canned ``Response`` objects and a fake waiter that records every
wait instead of sleeping.
"""

from __future__ import annotations

import logging
import threading
from http import HTTPStatus

import pytest
import requests

from avai.enrichers.base import RateLimitedError
from avai.enrichers.http import (
    MIN_RATE_PER_SECOND,
    RETRY_BACKOFFS_S,
    HostRateLimits,
    HttpCall,
    HttpClient,
    HttpMethod,
    HttpPacing,
    RequestOptions,
    SessionTransport,
    Waiter,
)

FAST_RATE = 1000.0
SLOW_RATE = MIN_RATE_PER_SECOND


def _resp(
    status: int, body: str = "ok", headers: dict[str, str] | None = None
) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response._content = body.encode()
    response.headers.update(headers or {})
    return response


class _FakeTransport(SessionTransport):
    """Raises ``errors`` in order, then hands out ``replies`` in order; the
    last reply (or, with none, the last error) repeats from then on."""

    def __init__(
        self,
        replies: list[requests.Response],
        errors: list[requests.RequestException],
    ) -> None:
        self.replies = replies
        self.errors = errors
        self.calls: list[HttpCall] = []

    def send(self, call: HttpCall) -> requests.Response:
        self.calls.append(call)
        attempt = len(self.calls) - 1
        if attempt < len(self.errors) or not self.replies:
            raise self.errors[min(attempt, len(self.errors) - 1)]
        return self.replies[min(attempt - len(self.errors), len(self.replies) - 1)]


class _FakeWaiter(Waiter):
    """Time moves only when the client waits; every wait is recorded."""

    MIDDLE_JITTER = 0.5  # a jitter factor of exactly 1.0

    def __init__(self) -> None:
        self.now = 0.0
        self.waits: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.waits.append(seconds)
        self.now += seconds

    def monotonic(self) -> float:
        return self.now

    def jitter(self) -> float:
        return self.MIDDLE_JITTER


class _Rig:
    """A client wired to a fake transport and a fake waiter."""

    def __init__(self, transport: _FakeTransport, waiter: _FakeWaiter) -> None:
        self.transport = transport
        self.waiter = waiter

    @classmethod
    def replying(cls, replies: list[requests.Response]) -> _Rig:
        return cls(_FakeTransport(replies, []), _FakeWaiter())

    @classmethod
    def failing(cls, errors: list[requests.RequestException]) -> _Rig:
        return cls(_FakeTransport([], errors), _FakeWaiter())

    def client(self) -> HttpClient:
        rates = HostRateLimits(FAST_RATE, threading.Lock(), self.waiter)
        pacing = HttpPacing(rates, self.waiter)
        return HttpClient(self.transport, pacing, logging.getLogger("test"))


class TestHostOf:
    def host_of(self, url: str) -> str:
        return HttpCall(HttpMethod.GET, url, RequestOptions()).host

    def test_extracts_host_from_https(self) -> None:
        assert self.host_of("https://api.example.com/x/y") == "api.example.com"

    def test_extracts_host_from_http(self) -> None:
        assert self.host_of("http://x.test/") == "x.test"

    def test_lowercases_host(self) -> None:
        assert self.host_of("https://API.Example.COM/") == "api.example.com"

    def test_returns_url_when_no_scheme(self) -> None:
        # Defensive — never raises, even on malformed input.
        assert self.host_of("not-a-url") == "not-a-url"


class TestUserAgent:
    def test_sets_user_agent_header(self) -> None:
        agent = SessionTransport.identified_session().headers["User-Agent"]
        assert agent.startswith("avai-monitor/")
        assert "github.com/iklobato/avai" in agent


class TestSuccessPath:
    def test_get_returns_response(self) -> None:
        rig = _Rig.replying([_resp(HTTPStatus.OK, "hi")])
        response = rig.client().get("https://api.test/")
        assert (response.status_code, response.text) == (HTTPStatus.OK, "hi")
        assert rig.transport.calls == [
            HttpCall(HttpMethod.GET, "https://api.test/", RequestOptions())
        ]

    def test_post_forwards_json(self) -> None:
        rig = _Rig.replying([_resp(HTTPStatus.OK, '{"ok":true}')])
        rig.client().post("https://api.test/", RequestOptions(json={"a": 1}))
        assert rig.transport.calls[0].options.json == {"a": 1}


class TestRateLimited429:
    SHORT_WAIT_S = 1.0

    def test_raises_on_429_without_retry_after(self) -> None:
        rig = _Rig.replying([_resp(HTTPStatus.TOO_MANY_REQUESTS)])
        with pytest.raises(RateLimitedError) as exc_info:
            rig.client().get("https://api.test/")
        assert str(exc_info.value) == "api.test returned 429"

    def test_raises_on_429_with_long_retry_after(self) -> None:
        # Retry-After=60 is too long; we surface as RateLimited, not block.
        throttled = _resp(HTTPStatus.TOO_MANY_REQUESTS, headers={"Retry-After": "60"})
        with pytest.raises(RateLimitedError):
            _Rig.replying([throttled]).client().get("https://api.test/")

    def test_retries_on_short_retry_after(self) -> None:
        # Retry-After=1 within the configured ceiling → retries.
        throttled = _resp(HTTPStatus.TOO_MANY_REQUESTS, headers={"Retry-After": "1"})
        rig = _Rig.replying([throttled, _resp(HTTPStatus.OK)])
        response = rig.client().get("https://api.test/")
        assert response.status_code == HTTPStatus.OK
        assert len(rig.transport.calls) == len(rig.transport.replies)
        assert self.SHORT_WAIT_S in rig.waiter.waits


class TestRetryOnTransient5xx:
    def test_retries_then_succeeds(self) -> None:
        rig = _Rig.replying(
            [
                _resp(HTTPStatus.SERVICE_UNAVAILABLE),
                _resp(HTTPStatus.INTERNAL_SERVER_ERROR),
                _resp(HTTPStatus.OK),
            ]
        )
        response = rig.client().get("https://api.test/")
        assert response.status_code == HTTPStatus.OK
        assert len(rig.transport.calls) == len(rig.transport.replies)

    def test_exhausts_retries_and_raises(self) -> None:
        rig = _Rig.replying([_resp(HTTPStatus.SERVICE_UNAVAILABLE)])
        with pytest.raises(requests.HTTPError) as exc_info:
            rig.client().get("https://api.test/")
        assert str(exc_info.value) == "503 from api.test"

    def test_waits_the_backoff_between_attempts(self) -> None:
        rig = _Rig.replying([_resp(HTTPStatus.SERVICE_UNAVAILABLE)])
        with pytest.raises(requests.HTTPError):
            rig.client().get("https://api.test/")
        assert rig.waiter.waits == pytest.approx(list(RETRY_BACKOFFS_S))


class TestNetworkErrors:
    def test_retries_after_connection_error(self) -> None:
        errors = [requests.ConnectionError("boom"), requests.ConnectionError("boom")]
        rig = _Rig(_FakeTransport([_resp(HTTPStatus.OK)], errors), _FakeWaiter())
        response = rig.client().get("https://api.test/")
        assert response.status_code == HTTPStatus.OK
        assert len(rig.transport.calls) == len(errors) + len(rig.transport.replies)

    def test_propagates_after_exhausting(self) -> None:
        rig = _Rig.failing([requests.ConnectionError("dead")])
        with pytest.raises(requests.ConnectionError) as exc_info:
            rig.client().get("https://api.test/")
        assert str(exc_info.value) == "dead"


class TestRateLimitBucket:
    def test_set_rate_overrides_default_per_host(self) -> None:
        # The slowest allowed rate: the first call is free, the second waits
        # out the whole period.
        rig = _Rig.replying([_resp(HTTPStatus.OK)])
        client = rig.client()
        client.set_rate("slow.test", SLOW_RATE)
        client.get("https://slow.test/")
        client.get("https://slow.test/")
        assert rig.waiter.waits == pytest.approx([1 / SLOW_RATE])

    def test_different_hosts_share_no_state(self) -> None:
        rig = _Rig.replying([_resp(HTTPStatus.OK)])
        client = rig.client()
        client.set_rate("slow.test", SLOW_RATE)
        client.set_rate("fast.test", FAST_RATE)
        client.get("https://slow.test/")  # consumes the slow bucket
        client.get("https://fast.test/")  # different bucket → free
        assert rig.waiter.waits == []
