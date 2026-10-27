"""LLM judging: the judge and cost estimation."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from .constants import (
    DEFAULT_JUDGE_BATCH,
    DEFAULT_JUDGE_MAX_PER_COLLECTOR,
    DEFAULT_JUDGE_MODEL,
)
from .enums import ThreatCategory, Verdict
from .llm_replies import JudgmentReply
from .llm import (
    CompletionError,
    CompletionRequest,
    LlmSession,
    StructuredCall,
)
from .prompts import Prompts
from .runtime import Clock


class ModelPricing:
    """Estimated USD cost of one completion, matched to a pricing tier by
    model-name substring (falls back to the cheapest)."""

    TOKENS_PER_PRICE_UNIT = 1_000_000
    # (model-name substring, (input $/Mtok, output $/Mtok))
    TIERS = (
        ("haiku", (1.0, 5.0)),
        ("sonnet", (3.0, 15.0)),
        ("opus", (15.0, 75.0)),
    )
    DEFAULT_RATES = (1.0, 5.0)

    def estimate(self, model: str, input_tokens: int, output_tokens: int) -> float:
        input_rate, output_rate = self._rates(model)
        tokens = input_tokens * input_rate + output_tokens * output_rate
        return tokens / self.TOKENS_PER_PRICE_UNIT

    def _rates(self, model: str) -> tuple[float, float]:
        name = (model or "").lower()
        tiers = (rates for key, rates in self.TIERS if key in name)
        return next(tiers, self.DEFAULT_RATES)


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
        self, collector: str, hints: str, entries: list[dict[str, Any]]
    ) -> list[Judgment]: ...


class NullJudge(Judge):
    def judge(
        self, collector: str, hints: str, entries: list[dict[str, Any]]
    ) -> list[Judgment]:
        return []


@dataclass(frozen=True)
class JudgeSettings:
    model: str = DEFAULT_JUDGE_MODEL
    batch_size: int = DEFAULT_JUDGE_BATCH
    # 0 means no cap.
    max_per_collector: int = DEFAULT_JUDGE_MAX_PER_COLLECTOR

    def effective_batch_size(self) -> int:
        # batch_size 0 would make range() raise and a negative one would judge
        # nothing; a bad --judge-batch-size must not break the cycle.
        return max(1, self.batch_size)


@dataclass(frozen=True)
class JudgeRequest:
    collector: str
    hints: str
    created_at: str


@dataclass(frozen=True)
class JudgmentStamp:
    """What every judgment from one batch shares."""

    collector: str
    model: str
    created_at: str
    cost_usd: float


class LlmJudge(Judge):
    """Threat judge backed by an LLM through the injected completion client.

    Structured output is enforced via the client's ``complete_structured``
    (JSON-mode for litellm, tool_use for OAuth). Either way the caller
    receives a dict directly.
    """

    SCHEMA_NAME = "submit_judgments"
    TEMPERATURE = 0.0
    MAX_TOKENS = 4096
    ERROR_EXCERPT_CHARS = 200
    REQUIRED = ("index", "verdict", "category", "confidence", "reasoning")

    def __init__(
        self, llm: StructuredCall, settings: JudgeSettings, clock: Clock
    ) -> None:
        self._llm = llm
        self._settings = settings
        self._clock = clock

    @classmethod
    def create(
        cls, prompts: Prompts, session: LlmSession, settings: JudgeSettings
    ) -> LlmJudge:
        request = CompletionRequest(
            model=settings.model,
            system=prompts.system,
            user=prompts.user_template,
            schema=cls._judgment_schema(),
            schema_name=cls.SCHEMA_NAME,
            max_tokens=cls.MAX_TOKENS,
            temperature=cls.TEMPERATURE,
        )
        return cls(StructuredCall("judge", session, request), settings, Clock())

    @classmethod
    def _judgment_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "judgments": {"type": "array", "items": cls._item_schema()},
            },
            "required": ["judgments"],
        }

    @classmethod
    def _item_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "index": {"type": "integer"},
                "verdict": {
                    "type": "string",
                    "enum": [str(verdict) for verdict in Verdict],
                },
                "category": {
                    "type": "string",
                    "enum": [str(category) for category in ThreatCategory],
                },
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "reasoning": {"type": "string"},
                "remediation": {"type": "string"},
            },
            "required": [*cls.REQUIRED, "remediation"],
        }

    @property
    def model(self) -> str:
        return self._settings.model

    @property
    def batch_size(self) -> int:
        return self._settings.effective_batch_size()

    def judge(
        self, collector: str, hints: str, entries: list[dict[str, Any]]
    ) -> list[Judgment]:
        request = JudgeRequest(collector, hints, self._clock.now_iso())
        results: list[Judgment] = []
        for batch in self._batches(self._capped(collector, entries)):
            try:
                results.extend(self._call(request, batch))
            except CompletionError as exc:
                self._llm.session.logger.warning(
                    "judge batch failed collector=%s error=%s msg=%s",
                    collector,
                    type(exc).__name__,
                    str(exc)[: self.ERROR_EXCERPT_CHARS],
                )
        return results

    def _capped(
        self, collector: str, entries: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        cap = self._settings.max_per_collector
        if not cap or len(entries) <= cap:
            return entries
        self._llm.session.logger.info(
            "judge collector=%s capping entries %d -> %d", collector, len(entries), cap
        )
        return entries[:cap]

    def _batches(self, entries: list[dict[str, Any]]) -> Iterator[list[dict[str, Any]]]:
        size = self.batch_size
        for start in range(0, len(entries), size):
            yield entries[start : start + size]

    def _call(
        self, request: JudgeRequest, batch: list[dict[str, Any]]
    ) -> list[Judgment]:
        entries = json.dumps(self._payload(batch), ensure_ascii=False)
        parsed = self._llm.ask(
            {"collector": request.collector, "hints": request.hints, "entries": entries}
        )
        # One API call judges the whole batch, so each entry bears an equal
        # share of its estimated cost.
        stamp = JudgmentStamp(
            request.collector, self.model, request.created_at, self._share(batch)
        )
        return [
            self._judgment(
                stamp, batch[index]["content_hash"], JudgmentReply.model_validate(item)
            )
            for index, item in self._indexed(parsed, len(batch))
        ]

    def _payload(self, batch: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "index": index,
                **{
                    key: value
                    for key, value in entry.items()
                    if key != "content_hash" and value is not None
                },
            }
            for index, entry in enumerate(batch)
        ]

    def _share(self, batch: list[dict[str, Any]]) -> float:
        usage = self._llm.last_usage()
        if not usage or not batch:
            return 0.0
        cost = ModelPricing().estimate(
            self.model, usage.get("input", 0), usage.get("output", 0)
        )
        return cost / len(batch)

    def _indexed(
        self, parsed: dict[str, Any], size: int
    ) -> list[tuple[int, dict[str, Any]]]:
        items = [
            item for item in parsed.get("judgments", []) or [] if isinstance(item, dict)
        ]
        return [
            (item["index"], item)
            for item in items
            if isinstance(item.get("index"), int) and 0 <= item["index"] < size
        ]

    def _judgment(
        self, stamp: JudgmentStamp, content_hash: str, reply: JudgmentReply
    ) -> Judgment:
        return Judgment(
            content_hash=content_hash,
            collector=stamp.collector,
            **reply.fields(),
            model=stamp.model,
            created_at=stamp.created_at,
            cost_usd=stamp.cost_usd,
        )
