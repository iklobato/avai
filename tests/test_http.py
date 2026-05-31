"""Tests for the shared HttpClient.

Locks down the parts of HTTP behaviour the enrichers depend on:
host parsing, per-host rate limiting, exponential backoff on
transient errors, 429 handling with and without Retry-After, and
exhaustion of the retry budget.

Network-free — every test patches ``requests.Session.request`` with
fakes that record calls and return canned ``Response`` objects.
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest
import requests

from avai.enrichers.base import RateLimitedError
from avai.enrichers.http import HttpClient


def _resp(status: int, body: str = "ok",
          headers: dict[str, str] | None = None) -> requests.Response:
    r = requests.Response()
    r.status_code = status
    r._content = body.encode() if isinstance(body, str) else body
    r.headers.update(headers or {})
    return r


@pytest.fixture
def fast_client(monkeypatch):
    """Client whose retry sleeps are reduced to zero so the suite
    runs fast even when exercising backoff paths."""
    monkeypatch.setattr("avai.enrichers.http._RETRY_BACKOFFS", (0.0, 0.0, 0.0))
    # Default rate of 1000 rps so rate-limit sleeps don't bite either,
    # except in the tests that explicitly override it.
    return HttpClient(default_rate=1000.0)


class TestHostOf:
    def test_extracts_host_from_https(self, fast_client):
        assert fast_client._host_of("https://api.example.com/x/y") == "api.example.com"

    def test_extracts_host_from_http(self, fast_client):
        assert fast_client._host_of("http://x.test/") == "x.test"

    def test_lowercases_host(self, fast_client):
        assert fast_client._host_of("https://API.Example.COM/") == "api.example.com"

    def test_returns_url_when_no_scheme(self, fast_client):
        # Defensive — never raises, even on malformed input.
        assert fast_client._host_of("not-a-url") == "not-a-url"


class TestUserAgent:
    def test_sets_user_agent_header(self, fast_client):
        ua = fast_client._session.headers["User-Agent"]
        assert ua.startswith("avai-monitor/")
        assert "github.com/iklobato/avai" in ua


class TestSuccessPath:
    def test_get_returns_response(self, fast_client):
        mock = MagicMock(return_value=_resp(200, "hi"))
        fast_client._session.request = mock
        r = fast_client.get("https://api.test/")
        assert r.status_code == 200
        assert r.text == "hi"
        mock.assert_called_once()
        args, kwargs = mock.call_args
        assert args == ("GET", "https://api.test/")

    def test_post_forwards_json(self, fast_client):
        mock = MagicMock(return_value=_resp(200, '{"ok":true}'))
        fast_client._session.request = mock
        fast_client.post("https://api.test/", json={"a": 1})
        _, kwargs = mock.call_args
        assert kwargs["json"] == {"a": 1}


class TestRateLimited429:
    def test_raises_on_429_without_retry_after(self, fast_client):
        fast_client._session.request = MagicMock(return_value=_resp(429))
        with pytest.raises(RateLimitedError) as exc_info:
            fast_client.get("https://api.test/")
        assert "api.test" in str(exc_info.value)

    def test_raises_on_429_with_long_retry_after(self, fast_client):
        # Retry-After=60 is too long; we surface as RateLimited, not block.
        fast_client._session.request = MagicMock(
            return_value=_resp(429, headers={"Retry-After": "60"}))
        with pytest.raises(RateLimitedError):
            fast_client.get("https://api.test/")

    def test_retries_on_short_retry_after(self, fast_client):
        # Retry-After=1 within the configured ceiling → retries.
        responses = [
            _resp(429, headers={"Retry-After": "1"}),
            _resp(200, "recovered"),
        ]
        mock = MagicMock(side_effect=responses)
        fast_client._session.request = mock
        with patch("time.sleep") as sleep:
            r = fast_client.get("https://api.test/")
        assert r.status_code == 200
        assert mock.call_count == 2
        # The respected wait must have been issued (1 s).
        assert any(args[0] == 1.0 for args, _ in sleep.call_args_list)


class TestRetryOnTransient5xx:
    def test_retries_then_succeeds(self, fast_client):
        responses = [_resp(503), _resp(500), _resp(200, "ok")]
        mock = MagicMock(side_effect=responses)
        fast_client._session.request = mock
        r = fast_client.get("https://api.test/")
        assert r.status_code == 200
        assert mock.call_count == 3

    def test_exhausts_retries_and_raises(self, fast_client):
        fast_client._session.request = MagicMock(return_value=_resp(503))
        with pytest.raises(requests.HTTPError) as exc_info:
            fast_client.get("https://api.test/")
        assert "503" in str(exc_info.value)


class TestNetworkErrors:
    def test_retries_after_connection_error(self, fast_client):
        mock = MagicMock(side_effect=[
            requests.ConnectionError("boom"),
            requests.ConnectionError("boom"),
            _resp(200, "ok"),
        ])
        fast_client._session.request = mock
        r = fast_client.get("https://api.test/")
        assert r.status_code == 200
        assert mock.call_count == 3

    def test_propagates_after_exhausting(self, fast_client):
        fast_client._session.request = MagicMock(
            side_effect=requests.ConnectionError("dead"))
        with pytest.raises(requests.ConnectionError):
            fast_client.get("https://api.test/")


class TestRateLimitBucket:
    def test_set_rate_overrides_default_per_host(self, fast_client):
        # Cheap proof the per-host bucket is wired: setting a 0.0001 rps
        # rate means the second call should be paced. We measure by
        # patching time.sleep and asserting it was called.
        fast_client.set_rate("slow.test", 0.0001)  # 10000 s between calls
        fast_client._session.request = MagicMock(return_value=_resp(200))
        with patch("time.sleep") as sleep:
            fast_client.get("https://slow.test/")
            fast_client.get("https://slow.test/")
        # First call free, second paced.
        sleeps = [args[0] for args, _ in sleep.call_args_list if args[0] > 0]
        assert sleeps, "expected at least one rate-limit sleep"

    def test_different_hosts_share_no_state(self, fast_client):
        fast_client.set_rate("slow.test", 0.0001)
        fast_client.set_rate("fast.test", 1000.0)
        fast_client._session.request = MagicMock(return_value=_resp(200))
        with patch("time.sleep") as sleep:
            fast_client.get("https://slow.test/")  # consumes the slow bucket
            fast_client.get("https://fast.test/")  # different bucket → free
        sleeps = [args[0] for args, _ in sleep.call_args_list if args[0] > 0]
        # No pace-out on the fast host.
        assert all(s < 0.01 for s in sleeps)
