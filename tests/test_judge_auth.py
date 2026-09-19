"""The LLM credential rule and the stage wiring built from it."""

from __future__ import annotations

from dataclasses import replace
from unittest.mock import patch

import pytest

from avai.host_monitor import llm
from avai.host_monitor.constants import DEFAULT_PROMPTS_PATH
from avai.host_monitor.judge import LlmJudge, NullJudge
from avai.host_monitor.llm import LlmCredentials
from avai.host_monitor.main import LlmStages, _build_parser
from avai.host_monitor.prompts import Prompts

OAUTH = {"CLAUDE_CODE_OAUTH_TOKEN": "oauth-token"}
ANTHROPIC = {"ANTHROPIC_API_KEY": "sk-ant"}
OPENAI = {"OPENAI_API_KEY": "sk-openai"}


@pytest.mark.parametrize(
    ("env", "has_litellm", "expected_client"),
    [
        pytest.param({}, True, None, id="no-credentials"),
        pytest.param({"CLAUDE_CODE_OAUTH_TOKEN": ""}, True, None, id="empty-oauth"),
        pytest.param(OAUTH, False, "oauth", id="oauth-without-litellm"),
        pytest.param(ANTHROPIC, True, "litellm", id="anthropic-key"),
        pytest.param(OPENAI, True, "litellm", id="openai-key"),
        pytest.param(ANTHROPIC, False, None, id="key-without-litellm"),
        pytest.param({**OAUTH, **ANTHROPIC}, True, "oauth", id="oauth-wins"),
    ],
)
def test_credential_rule(monkeypatch, env, has_litellm, expected_client):
    monkeypatch.setattr(llm, "HAS_LITELLM", has_litellm)
    credentials = LlmCredentials.from_env(env)

    with (
        patch.object(llm, "AnthropicOAuthClient") as oauth,
        patch.object(llm, "LitellmClient") as litellm_client,
    ):
        picked = {oauth.return_value: "oauth", litellm_client.return_value: "litellm"}
        client = picked[credentials.client()] if credentials.can_call() else None

    assert client == expected_client


def test_oauth_client_is_built_with_the_token():
    with patch.object(llm, "AnthropicOAuthClient") as oauth:
        LlmCredentials.from_env(OAUTH).client()

    oauth.assert_called_once_with("oauth-token")


def test_token_stays_out_of_the_repr():
    assert "oauth-token" not in repr(LlmCredentials.from_env(OAUTH))


class _StubCredentials:
    def __init__(self, can_call=True, error: Exception | None = None):
        self._can_call = can_call
        self._error = error
        self.clients_built = 0

    def can_call(self):
        return self._can_call

    def client(self):
        self.clients_built += 1
        if self._error is not None:
            raise self._error
        return object()


def _args(*flags):
    return _build_parser().parse_args(list(flags))


def _stages(*flags, prompts=None, credentials=None):
    return LlmStages.build(
        _args(*flags),
        prompts or Prompts.load(DEFAULT_PROMPTS_PATH),
        credentials or _StubCredentials(),
    )


def _enabled(stages):
    return {
        name
        for name in ("narrator", "coverage", "verifier", "investigator")
        if getattr(stages, name) is not None
    }


ALL_OPTIONAL = {"narrator", "coverage", "verifier", "investigator"}


class TestLlmStagesBuild:
    def test_every_stage_shares_one_client(self):
        credentials = _StubCredentials()

        stages = _stages(credentials=credentials)

        assert isinstance(stages.judge, LlmJudge)
        assert _enabled(stages) == ALL_OPTIONAL
        assert credentials.clients_built == 1

    def test_no_credentials_turns_every_stage_off(self):
        credentials = _StubCredentials(can_call=False)

        stages = _stages(credentials=credentials)

        assert isinstance(stages.judge, NullJudge)
        assert _enabled(stages) == set()
        assert credentials.clients_built == 0

    def test_missing_sdk_turns_every_stage_off(self):
        stages = _stages(credentials=_StubCredentials(error=RuntimeError("no sdk")))

        assert isinstance(stages.judge, NullJudge)
        assert _enabled(stages) == set()

    def test_no_judge_also_drops_the_narrator_only(self):
        stages = _stages("--no-judge")

        assert isinstance(stages.judge, NullJudge)
        assert _enabled(stages) == ALL_OPTIONAL - {"narrator"}

    @pytest.mark.parametrize(
        ("flag", "stage"),
        [
            ("--no-narrative", "narrator"),
            ("--no-coverage", "coverage"),
            ("--no-verify", "verifier"),
            ("--no-investigate", "investigator"),
        ],
    )
    def test_each_flag_turns_off_its_stage(self, flag, stage):
        stages = _stages(flag)

        assert isinstance(stages.judge, LlmJudge)
        assert _enabled(stages) == ALL_OPTIONAL - {stage}

    def test_missing_prompt_turns_off_its_stage(self):
        prompts = replace(Prompts.load(DEFAULT_PROMPTS_PATH), verifier_system="")

        stages = _stages(prompts=prompts)

        assert _enabled(stages) == ALL_OPTIONAL - {"verifier"}
