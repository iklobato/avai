"""Tests for Sentry initialization in :mod:`avai.observability`.

Reporting is ON by default (bundled DSN) so failures users hit are visible
centrally; AVAI_TELEMETRY=0 or an empty SENTRY_DSN opts out. When on, PII is
off and LOG.warning-and-above is promoted to issues.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

from avai import __version__
from avai.observability import _DEFAULT_DSN, init_sentry


def _clear_env(monkeypatch):
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    monkeypatch.delenv("AVAI_TELEMETRY", raising=False)


class TestInitSentry:
    def test_default_initializes_with_bundled_dsn(self, monkeypatch):
        _clear_env(monkeypatch)
        with patch("sentry_sdk.init") as init:
            assert init_sentry() is True
        init.assert_called_once()
        kwargs = init.call_args.kwargs
        assert kwargs["dsn"] == _DEFAULT_DSN
        assert kwargs["release"] == f"avai@{__version__}"
        assert kwargs["send_default_pii"] is False

    def test_warning_level_promoted_to_issues(self, monkeypatch):
        _clear_env(monkeypatch)
        with patch("sentry_sdk.init") as init:
            init_sentry()
        from sentry_sdk.integrations.logging import LoggingIntegration

        integrations = init.call_args.kwargs["integrations"]
        logging_integration = next(
            i for i in integrations if isinstance(i, LoggingIntegration)
        )
        # The event handler fires at WARNING, not just the default ERROR.
        assert logging_integration._handler.level == logging.WARNING

    def test_sentry_dsn_overrides_bundled_default(self, monkeypatch):
        _clear_env(monkeypatch)
        monkeypatch.setenv("SENTRY_DSN", "https://custom@o0.ingest.us.sentry.io/9")
        with patch("sentry_sdk.init") as init:
            assert init_sentry() is True
        assert init.call_args.kwargs["dsn"] == "https://custom@o0.ingest.us.sentry.io/9"

    @pytest.mark.parametrize("value", ["0", "false", "no", "off", ""])
    def test_avai_telemetry_falsy_opts_out(self, monkeypatch, value):
        _clear_env(monkeypatch)
        monkeypatch.setenv("AVAI_TELEMETRY", value)
        with patch("sentry_sdk.init") as init:
            assert init_sentry() is False
        init.assert_not_called()

    def test_empty_sentry_dsn_opts_out(self, monkeypatch):
        _clear_env(monkeypatch)
        monkeypatch.setenv("SENTRY_DSN", "")
        with patch("sentry_sdk.init") as init:
            assert init_sentry() is False
        init.assert_not_called()

    def test_telemetry_on_keeps_reporting(self, monkeypatch):
        _clear_env(monkeypatch)
        monkeypatch.setenv("AVAI_TELEMETRY", "1")
        with patch("sentry_sdk.init") as init:
            assert init_sentry() is True
        init.assert_called_once()
