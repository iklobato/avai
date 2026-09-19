"""LLM plumbing shared by every stage: credentials, completion clients, and
the structured call each stage makes."""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from string import Template
from typing import Optional

try:
    # Quiet litellm's per-import warnings about optional AWS deps.
    os.environ.setdefault("LITELLM_LOG", "ERROR")
    import litellm

    HAS_LITELLM = True
except ImportError:
    HAS_LITELLM = False

from .constants import DEFAULT_JUDGE_TIMEOUT_S, LOG


@dataclass(frozen=True)
class CompletionRequest:
    model: str
    system: str
    user: str
    schema: dict
    schema_name: str
    max_tokens: int
    temperature: float


class CompletionClient(ABC):
    """Strategy for issuing an LLM chat completion that returns
    structured output matching a JSON schema. Returns a dict: no
    text-level JSON parsing happens in the caller."""

    @abstractmethod
    def complete_structured(self, request: CompletionRequest) -> dict: ...


class LitellmClient(CompletionClient):
    """Multi-provider completion via litellm. Uses ANTHROPIC_API_KEY /
    OPENAI_API_KEY / ... from the environment per litellm conventions.
    Forces JSON output via ``response_format``."""

    def __init__(self):
        if not HAS_LITELLM:
            raise RuntimeError(
                "litellm is required for LitellmClient: pip install litellm"
            )
        # Token usage of the most recent call ({"input","output"}); the judge
        # reads it to attribute cost. None when unavailable.
        self.last_usage: Optional[dict] = None

    def complete_structured(self, request):
        self.last_usage = None
        response = litellm.completion(
            model=request.model,
            messages=[
                {"role": "system", "content": request.system},
                {"role": "user", "content": request.user},
            ],
            response_format={"type": "json_object"},
            temperature=request.temperature,
            max_tokens=request.max_tokens,
            timeout=DEFAULT_JUDGE_TIMEOUT_S,
        )
        try:
            u = response.usage
            self.last_usage = {
                "input": int(u.prompt_tokens or 0),
                "output": int(u.completion_tokens or 0),
            }
        except Exception:
            self.last_usage = None
        return json.loads(response.choices[0].message.content)


class AnthropicOAuthClient(CompletionClient):
    """Anthropic completion via the OAuth Bearer flow used by Claude Code
    subscriptions. Sends ``Authorization: Bearer <token>`` plus the OAuth
    beta header. Bypasses litellm because litellm sends ``x-api-key`` which
    is incompatible with OAuth tokens.

    The Claude Code OAuth scope requires the system prompt to start with
    the Claude Code identity line. Structured output is obtained via
    ``tool_use`` (not free-text JSON) so we never have to strip markdown
    fences or parse arbitrary text.
    """

    OAUTH_BETA_HEADER = "oauth-2025-04-20"
    SYSTEM_PROMPT_PREFIX = "You are Claude Code, Anthropic's official CLI for Claude."

    def __init__(self, oauth_token: str):
        try:
            from anthropic import Anthropic
        except ImportError as e:
            raise RuntimeError(
                "anthropic SDK is required for OAuth auth: pip install anthropic"
            ) from e
        self._client = Anthropic(
            auth_token=oauth_token,
            default_headers={"anthropic-beta": self.OAUTH_BETA_HEADER},
            timeout=DEFAULT_JUDGE_TIMEOUT_S,
            max_retries=2,
        )
        self.last_usage: Optional[dict] = None

    def complete_structured(self, request):
        # Strip litellm-style provider prefix if present.
        model = request.model.split("/", 1)[-1]
        schema_name = request.schema_name
        tool = {
            "name": schema_name,
            "description": f"Submit results matching the {schema_name} schema.",
            "input_schema": request.schema,
        }
        self.last_usage = None
        response = self._client.messages.create(
            model=model,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            system=f"{self.SYSTEM_PROMPT_PREFIX}\n\n{request.system}",
            tools=[tool],
            tool_choice={"type": "tool", "name": schema_name},
            messages=[{"role": "user", "content": request.user}],
        )
        try:
            u = response.usage
            self.last_usage = {
                "input": int(u.input_tokens or 0),
                "output": int(u.output_tokens or 0),
            }
        except Exception:
            self.last_usage = None
        for block in response.content:
            if block.type == "tool_use" and block.name == schema_name:
                return dict(block.input)
        raise RuntimeError(
            f"OAuth response had no tool_use block (stop_reason={response.stop_reason})"
        )


@dataclass(frozen=True)
class LlmCredentials:
    """The LLM auth the environment offers, read once at the composition root."""

    oauth_token: Optional[str] = field(default=None, repr=False)
    has_api_key: bool = False

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> LlmCredentials:
        return cls(
            oauth_token=environ.get("CLAUDE_CODE_OAUTH_TOKEN") or None,
            has_api_key=bool(
                environ.get("ANTHROPIC_API_KEY") or environ.get("OPENAI_API_KEY")
            ),
        )

    def can_call(self) -> bool:
        # OAuth goes through the Anthropic SDK; an API key needs litellm.
        return bool(self.oauth_token) or (self.has_api_key and HAS_LITELLM)

    def client(self) -> CompletionClient:
        """Raises RuntimeError when the provider SDK is missing."""
        if self.oauth_token:
            return AnthropicOAuthClient(self.oauth_token)
        return LitellmClient()


@dataclass(frozen=True)
class StructuredCall:
    """One stage's fixed LLM call. ``request.user`` holds the user prompt
    template; each call renders it with that call's fields."""

    label: str
    client: CompletionClient
    request: CompletionRequest

    def ask(self, **fields) -> dict:
        user = Template(self.request.user).safe_substitute(**fields)
        return self.client.complete_structured(replace(self.request, user=user))

    def ask_or_none(self, **fields) -> Optional[dict]:
        """Never raises: a failed stage must not abort the cycle."""
        try:
            return self.ask(**fields)
        except Exception as exc:
            LOG.warning(
                "%s failed error=%s msg=%s",
                self.label,
                type(exc).__name__,
                str(exc)[:200],
            )
            return None
