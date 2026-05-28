"""Tests for the judge auth-strategy selection (`build_completion_client`)
and the `build_judge` factory's graceful degradation paths.
"""
from __future__ import annotations

import sys
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _reset_judge_creds(monkeypatch):
    for var in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY",
                "OPENAI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    yield


class TestBuildCompletionClient:
    def test_oauth_token_picks_anthropic_oauth_client(self, monkeypatch):
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat...")
        # Avoid actually building the SDK client (requires anthropic
        # package + network) by patching the class.
        with patch("avai.host_monitor.AnthropicOAuthClient") as oauth_cls:
            from avai.host_monitor import build_completion_client
            build_completion_client()
        oauth_cls.assert_called_once_with("sk-ant-oat...")

    def test_api_key_picks_litellm_client(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-...")
        with patch("avai.host_monitor.LitellmClient") as lc:
            from avai.host_monitor import build_completion_client
            build_completion_client()
        lc.assert_called_once_with()

    def test_oauth_takes_precedence_over_api_key(self, monkeypatch):
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "apikey")
        with patch("avai.host_monitor.AnthropicOAuthClient") as oauth_cls, \
             patch("avai.host_monitor.LitellmClient") as lc:
            from avai.host_monitor import build_completion_client
            build_completion_client()
        oauth_cls.assert_called_once()
        lc.assert_not_called()


class TestBuildJudge:
    def _args(self, **overrides):
        from argparse import Namespace
        defaults = dict(no_judge=False, judge_model="claude-haiku",
                        judge_batch_size=20, judge_max_per_collector=60)
        defaults.update(overrides)
        return Namespace(**defaults)

    def _prompts(self, tmp_path):
        from avai.host_monitor import Prompts
        return Prompts(system="ok", user_template="$collector $hints $entries",
                       collector_hints={})

    def test_no_judge_flag_returns_null_judge(self, tmp_path):
        from avai.host_monitor import build_judge, NullJudge
        j = build_judge(self._args(no_judge=True), self._prompts(tmp_path))
        assert isinstance(j, NullJudge)

    def test_missing_creds_returns_null_judge(self, tmp_path):
        # No env, no --no-judge — should still degrade gracefully.
        from avai.host_monitor import build_judge, NullJudge
        j = build_judge(self._args(), self._prompts(tmp_path))
        assert isinstance(j, NullJudge)

    def test_oauth_present_constructs_llm_judge(self, monkeypatch, tmp_path):
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat")
        with patch("avai.host_monitor.LlmJudge") as llm:
            llm.return_value.auth_mode = "AnthropicOAuthClient"
            llm.return_value.model = "claude-haiku"
            from avai.host_monitor import build_judge
            j = build_judge(self._args(), self._prompts(tmp_path))
        assert llm.called
        assert j is llm.return_value
