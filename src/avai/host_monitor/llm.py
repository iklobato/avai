"""LLM plumbing shared by every stage: credentials, completion clients, and
the structured call each stage makes."""

from __future__ import annotations

import importlib
import json
import logging
import os
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from string import Template
from typing import Any

from anthropic import Anthropic
from anthropic import APIError as AnthropicApiError

from .constants import DEFAULT_JUDGE_TIMEOUT_S


class CompletionError(RuntimeError):
    """An LLM call failed or returned a response with no usable result."""


@dataclass(frozen=True)
class CompletionRequest:
    model: str
    system: str
    user: str
    schema: dict[str, Any]
    schema_name: str
    max_tokens: int
    temperature: float


class CompletionClient(ABC):
    """Strategy for issuing an LLM chat completion that returns
    structured output matching a JSON schema. Returns a dict: no
    text-level JSON parsing happens in the caller."""

    # Token usage of the most recent call ({"input","output"}); the judge
    # reads it to attribute cost. None when unavailable.
    last_usage: dict[str, int] | None = None

    @abstractmethod
    def complete_structured(self, request: CompletionRequest) -> dict[str, Any]: ...


@dataclass(frozen=True)
class LitellmApi:
    """The litellm entry points the client needs. Loaded lazily so
    ``LITELLM_LOG`` is set before litellm reads it at import time."""

    completion: Callable[..., Any]
    error: type[Exception]

    @classmethod
    def load(cls) -> LitellmApi:
        # Quiet litellm's per-import warnings about optional AWS deps.
        os.environ.setdefault("LITELLM_LOG", "ERROR")
        litellm = importlib.import_module("litellm")
        return cls(litellm.completion, litellm.exceptions.OpenAIError)


class LitellmClient(CompletionClient):
    """Multi-provider completion via litellm. Uses ANTHROPIC_API_KEY /
    OPENAI_API_KEY / ... from the environment per litellm conventions.
    Forces JSON output via ``response_format``."""

    def __init__(self, api: LitellmApi) -> None:
        self._api = api
        self.last_usage = None

    @classmethod
    def create(cls) -> LitellmClient:
        return cls(LitellmApi.load())

    def complete_structured(self, request: CompletionRequest) -> dict[str, Any]:
        self.last_usage = None
        try:
            response = self._api.completion(
                model=request.model,
                messages=self._messages(request),
                response_format={"type": "json_object"},
                temperature=request.temperature,
                max_tokens=request.max_tokens,
                timeout=DEFAULT_JUDGE_TIMEOUT_S,
            )
        except self._api.error as exc:
            raise CompletionError(f"litellm call failed: {exc}") from exc
        self.last_usage = self._usage(response)
        return self._content(response)

    def _messages(self, request: CompletionRequest) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": request.system},
            {"role": "user", "content": request.user},
        ]

    def _usage(self, response: Any) -> dict[str, int] | None:
        try:
            usage = response.usage
            return {
                "input": int(usage.prompt_tokens or 0),
                "output": int(usage.completion_tokens or 0),
            }
        except (AttributeError, TypeError, ValueError):
            return None

    def _content(self, response: Any) -> dict[str, Any]:
        try:
            return dict(json.loads(response.choices[0].message.content))
        except (AttributeError, IndexError, TypeError, ValueError) as exc:
            raise CompletionError("litellm response carried no JSON object") from exc


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
    MAX_RETRIES = 2

    def __init__(self, client: Anthropic) -> None:
        self._client = client
        self.last_usage = None

    @classmethod
    def create(cls, oauth_token: str) -> AnthropicOAuthClient:
        return cls(
            Anthropic(
                auth_token=oauth_token,
                default_headers={"anthropic-beta": cls.OAUTH_BETA_HEADER},
                timeout=DEFAULT_JUDGE_TIMEOUT_S,
                max_retries=cls.MAX_RETRIES,
            )
        )

    def complete_structured(self, request: CompletionRequest) -> dict[str, Any]:
        self.last_usage = None
        try:
            response = self._send(request)
        except AnthropicApiError as exc:
            raise CompletionError(f"anthropic call failed: {exc}") from exc
        self.last_usage = self._usage(response)
        return self._tool_input(response, request.schema_name)

    def _send(self, request: CompletionRequest) -> Any:
        schema_name = request.schema_name
        tool = {
            "name": schema_name,
            "description": f"Submit results matching the {schema_name} schema.",
            "input_schema": request.schema,
        }
        return self._client.messages.create(
            # Strip litellm-style provider prefix if present.
            model=request.model.split("/", 1)[-1],
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            system=f"{self.SYSTEM_PROMPT_PREFIX}\n\n{request.system}",
            tools=[tool],
            tool_choice={"type": "tool", "name": schema_name},
            messages=[{"role": "user", "content": request.user}],
        )

    def _usage(self, response: Any) -> dict[str, int] | None:
        try:
            usage = response.usage
            return {
                "input": int(usage.input_tokens or 0),
                "output": int(usage.output_tokens or 0),
            }
        except (AttributeError, TypeError, ValueError):
            return None

    def _tool_input(self, response: Any, schema_name: str) -> dict[str, Any]:
        blocks = (
            block
            for block in response.content
            if block.type == "tool_use" and block.name == schema_name
        )
        block = next(blocks, None)
        if block is None:
            raise CompletionError(
                f"OAuth response had no tool_use block (stop_reason={response.stop_reason})"
            )
        return dict(block.input)


@dataclass(frozen=True)
class LlmCredentials:
    """The LLM auth the environment offers, read once at the composition root."""

    oauth_token: str | None = field(default=None, repr=False)
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
        return bool(self.oauth_token) or self.has_api_key

    def client(self) -> CompletionClient:
        # OAuth goes through the Anthropic SDK; an API key goes through litellm.
        if self.oauth_token:
            return AnthropicOAuthClient.create(self.oauth_token)
        return LitellmClient.create()


class ParsedReply:
    """Reads a model's structured reply defensively: any field may be
    missing, empty, or of the wrong type."""

    def __init__(self, fields: Mapping[str, Any]) -> None:
        self._fields = fields

    def text(self, key: str, limit: int) -> str:
        return str(self._fields.get(key) or "").strip()[:limit]

    def raw_text(self, key: str, limit: int) -> str:
        """The field as text, cut to ``limit`` but not stripped."""
        return str(self._fields.get(key) or "")[:limit]

    def keyword(self, key: str) -> str:
        return str(self._fields.get(key) or "").strip().lower()

    def choice(self, key: str, allowed: tuple[str, ...], fallback: str) -> str:
        value = self.keyword(key)
        return value if value in allowed else fallback

    def flag(self, key: str) -> bool:
        return bool(self._fields.get(key))

    def fraction(self, key: str) -> float:
        """A number clamped to ``[0, 1]``; 0.0 when absent or not numeric."""
        try:
            value = float(self._fields.get(key) or 0.0)
        except (TypeError, ValueError):
            return 0.0
        return max(0.0, min(1.0, value))

    def entries(self, key: str, label_key: str) -> list[ParsedReply]:
        """The objects of an array field whose ``label_key`` is non-empty."""
        items = self._fields.get(key) or []
        replies = [ParsedReply(item) for item in items if isinstance(item, dict)]
        return [reply for reply in replies if reply.text(label_key, 1)]


@dataclass(frozen=True)
class LlmSession:
    """What every stage shares: the completion client and where to log."""

    client: CompletionClient
    logger: logging.Logger


@dataclass(frozen=True)
class StructuredCall:
    """One stage's fixed LLM call. ``request.user`` holds the user prompt
    template; each call renders it with that call's fields."""

    ERROR_EXCERPT_CHARS = 200

    label: str
    session: LlmSession
    request: CompletionRequest

    def ask(self, fields: Mapping[str, str]) -> dict[str, Any]:
        user = Template(self.request.user).safe_substitute(fields)
        request = replace(self.request, user=user)
        return self.session.client.complete_structured(request)

    def ask_or_none(self, fields: Mapping[str, str]) -> dict[str, Any] | None:
        """A failed call returns None: a failed stage must not abort the cycle."""
        try:
            return self.ask(fields)
        except CompletionError as exc:
            self.session.logger.warning(
                "%s failed error=%s msg=%s",
                self.label,
                type(exc).__name__,
                str(exc)[: self.ERROR_EXCERPT_CHARS],
            )
            return None

    def last_usage(self) -> dict[str, int] | None:
        return self.session.client.last_usage
