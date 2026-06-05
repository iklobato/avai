"""LLM judging: completion clients, the judge, and cost estimation."""
from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from string import Template
from typing import Optional

try:
    # Quiet litellm's per-import warnings about optional AWS deps.
    os.environ.setdefault("LITELLM_LOG", "ERROR")
    import litellm

    HAS_LITELLM = True
except ImportError:
    HAS_LITELLM = False

from .enums import ThreatCategory, Verdict
from .constants import DEFAULT_JUDGE_BATCH, DEFAULT_JUDGE_MAX_PER_COLLECTOR, DEFAULT_JUDGE_MODEL, DEFAULT_JUDGE_TIMEOUT_S, DEFAULT_PRICING, LOG, MODEL_PRICING
from .runtime import Clock, Coerce
from .prompts import Prompts


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimated USD cost for one completion given its token counts, matched
    to a pricing tier by model-name substring (falls back to the cheapest)."""
    in_rate, out_rate = DEFAULT_PRICING
    m = (model or "").lower()
    for key, rates in MODEL_PRICING.items():
        if key in m:
            in_rate, out_rate = rates
            break
    return (input_tokens / 1_000_000) * in_rate + (output_tokens / 1_000_000) * out_rate


@dataclass(frozen=True)
class Judgment:
    content_hash: str
    collector: str
    verdict: Verdict
    category: ThreatCategory
    confidence: float
    reasoning: str
    remediation: str
    model: str
    created_at: str
    # Estimated USD cost attributed to this entry (its share of the batch's
    # LLM call). 0.0 when usage/cost is unavailable (e.g. NullJudge, mocks).
    cost_usd: float = 0.0


class Judge(ABC):
    """Classifies entries as security threats."""

    @abstractmethod
    def judge(
        self, collector: str, hints: str, entries: list[dict]
    ) -> list[Judgment]: ...


class NullJudge(Judge):
    def judge(self, collector, hints, entries):
        return []


class CompletionClient(ABC):
    """Strategy for issuing an LLM chat completion that returns
    structured output matching a JSON schema. Returns a dict — no
    text-level JSON parsing happens in the caller."""

    @abstractmethod
    def complete_structured(
        self,
        *,
        model: str,
        system: str,
        user: str,
        max_tokens: int,
        temperature: float,
        schema: dict,
        schema_name: str,
    ) -> dict: ...


class LitellmClient(CompletionClient):
    """Multi-provider completion via litellm. Uses ANTHROPIC_API_KEY /
    OPENAI_API_KEY / ... from the environment per litellm conventions.
    Forces JSON output via ``response_format``."""

    def __init__(self):
        if not HAS_LITELLM:
            raise RuntimeError(
                "litellm is required for LitellmClient — pip install litellm"
            )
        # Token usage of the most recent call ({"input","output"}); the judge
        # reads it to attribute cost. None when unavailable.
        self.last_usage: Optional[dict] = None

    def complete_structured(
        self, *, model, system, user, max_tokens, temperature, schema, schema_name
    ):
        self.last_usage = None
        response = litellm.completion(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            response_format={"type": "json_object"},
            temperature=temperature,
            max_tokens=max_tokens,
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
    subscriptions. Reads ``CLAUDE_CODE_OAUTH_TOKEN`` from the environment
    and sends ``Authorization: Bearer <token>`` plus the OAuth beta
    header. Bypasses litellm because litellm sends ``x-api-key`` which
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
                "anthropic SDK is required for OAuth auth — " "pip install anthropic"
            ) from e
        self._client = Anthropic(
            auth_token=oauth_token,
            default_headers={"anthropic-beta": self.OAUTH_BETA_HEADER},
            timeout=DEFAULT_JUDGE_TIMEOUT_S,
            max_retries=2,
        )
        self.last_usage: Optional[dict] = None

    def complete_structured(
        self, *, model, system, user, max_tokens, temperature, schema, schema_name
    ):
        # Strip litellm-style provider prefix if present.
        if "/" in model:
            model = model.split("/", 1)[1]
        full_system = f"{self.SYSTEM_PROMPT_PREFIX}\n\n{system}"
        tool = {
            "name": schema_name,
            "description": f"Submit results matching the {schema_name} schema.",
            "input_schema": schema,
        }
        self.last_usage = None
        response = self._client.messages.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=full_system,
            tools=[tool],
            tool_choice={"type": "tool", "name": schema_name},
            messages=[{"role": "user", "content": user}],
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
            f"OAuth response had no tool_use block (stop_reason="
            f"{response.stop_reason})"
        )


def build_completion_client() -> CompletionClient:
    """Pick the right strategy from the environment.

    - ``CLAUDE_CODE_OAUTH_TOKEN`` set → ``AnthropicOAuthClient``
    - otherwise → ``LitellmClient`` (which itself reads
      ``ANTHROPIC_API_KEY`` / ``OPENAI_API_KEY`` / ...)
    """
    oauth = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
    if oauth:
        return AnthropicOAuthClient(oauth)
    return LitellmClient()


class LlmJudge(Judge):
    """Threat judge backed by an LLM. Auth strategy is decided by
    ``build_completion_client()`` (OAuth → Anthropic SDK; API key →
    litellm). Prompts are injected via the ``Prompts`` object.

    Structured output is enforced via the client's
    ``complete_structured`` — JSON-mode for litellm, tool_use for OAuth.
    Either way the caller receives a dict directly.
    """

    SCHEMA_NAME = "submit_judgments"

    @classmethod
    def _judgment_schema(cls) -> dict:
        return {
            "type": "object",
            "properties": {
                "judgments": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "index": {"type": "integer"},
                            "verdict": {
                                "type": "string",
                                "enum": [str(v) for v in Verdict],
                            },
                            "category": {
                                "type": "string",
                                "enum": [str(c) for c in ThreatCategory],
                            },
                            "confidence": {
                                "type": "number",
                                "minimum": 0,
                                "maximum": 1,
                            },
                            "reasoning": {"type": "string"},
                            "remediation": {"type": "string"},
                        },
                        "required": [
                            "index",
                            "verdict",
                            "category",
                            "confidence",
                            "reasoning",
                            "remediation",
                        ],
                    },
                },
            },
            "required": ["judgments"],
        }

    def __init__(
        self,
        prompts: Prompts,
        model: str = DEFAULT_JUDGE_MODEL,
        batch_size: int = DEFAULT_JUDGE_BATCH,
        max_per_collector: int = DEFAULT_JUDGE_MAX_PER_COLLECTOR,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        client: Optional[CompletionClient] = None,
    ):
        self.prompts = prompts
        self.model = model
        self.batch_size = batch_size
        self.max_per_collector = max_per_collector
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._user_template = Template(prompts.user_template)
        self._client = client or build_completion_client()
        self._schema = self._judgment_schema()

    @property
    def auth_mode(self) -> str:
        return type(self._client).__name__

    def judge(self, collector, hints, entries):
        if not entries:
            return []
        if self.max_per_collector and len(entries) > self.max_per_collector:
            LOG.info(
                "judge collector=%s capping entries %d -> %d",
                collector,
                len(entries),
                self.max_per_collector,
            )
            entries = entries[: self.max_per_collector]

        now = Clock().now_iso()
        results: list[Judgment] = []
        for batch in self._batches(entries):
            try:
                results.extend(self._call(collector, hints, batch, now))
            except Exception as exc:
                LOG.warning(
                    "judge batch failed collector=%s error=%s msg=%s",
                    collector,
                    type(exc).__name__,
                    str(exc)[:200],
                )
        return results

    def _batches(self, entries):
        for i in range(0, len(entries), self.batch_size):
            yield entries[i : i + self.batch_size]

    def _call(self, collector, hints, batch, now):
        payload = [
            {
                "index": i,
                **{k: v for k, v in e.items() if k != "content_hash" and v is not None},
            }
            for i, e in enumerate(batch)
        ]
        user = self._user_template.safe_substitute(
            collector=collector,
            hints=hints,
            entries=json.dumps(payload, ensure_ascii=False),
        )
        parsed = self._client.complete_structured(
            model=self.model,
            system=self.prompts.system,
            user=user,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            schema=self._schema,
            schema_name=self.SCHEMA_NAME,
        )
        # Attribute the call's estimated cost evenly across the batch's
        # entries — one API call judges the whole batch, so each entry bears
        # an equal share.
        usage = getattr(self._client, "last_usage", None)
        call_cost = (
            estimate_cost(self.model, usage.get("input", 0), usage.get("output", 0))
            if usage
            else 0.0
        )
        per_entry = call_cost / len(batch) if batch else 0.0
        return list(self._parse(parsed, batch, collector, now, per_entry))

    def _parse(self, parsed, batch, collector, now, cost_usd=0.0):
        for item in parsed.get("judgments", []) or []:
            idx = item.get("index")
            if not isinstance(idx, int) or not (0 <= idx < len(batch)):
                continue
            try:
                confidence = float(item.get("confidence") or 0.0)
            except (TypeError, ValueError):
                confidence = 0.0
            yield Judgment(
                content_hash=batch[idx]["content_hash"],
                collector=collector,
                verdict=Coerce.enum(item.get("verdict"), Verdict, Verdict.UNKNOWN),
                category=Coerce.enum(
                    item.get("category"), ThreatCategory, ThreatCategory.NONE
                ),
                confidence=max(0.0, min(1.0, confidence)),
                reasoning=str(item.get("reasoning") or "")[:500],
                remediation=str(item.get("remediation") or "")[:2000],
                model=self.model,
                created_at=now,
                cost_usd=cost_usd,
            )


def build_judge(args, prompts: Prompts) -> Judge:
    if args.no_judge:
        LOG.info("judge disabled (--no-judge)")
        return NullJudge()
    has_oauth = bool(os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"))
    has_api_key = bool(
        os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY")
    )
    if not has_oauth and not has_api_key:
        LOG.warning(
            "no LLM credentials in environment "
            "(CLAUDE_CODE_OAUTH_TOKEN / ANTHROPIC_API_KEY / OPENAI_API_KEY) — "
            "threat judging disabled"
        )
        return NullJudge()
    if not has_oauth and not HAS_LITELLM:
        LOG.warning(
            "litellm not installed and no OAuth token; threat "
            "judging disabled. pip install litellm"
        )
        return NullJudge()
    try:
        judge = LlmJudge(
            prompts=prompts,
            model=args.judge_model,
            batch_size=args.judge_batch_size,
            max_per_collector=args.judge_max_per_collector,
        )
    except RuntimeError as exc:
        LOG.warning("LlmJudge unavailable (%s); falling back to NullJudge", exc)
        return NullJudge()
    LOG.info("judge auth_mode=%s model=%s", judge.auth_mode, judge.model)
    return judge
