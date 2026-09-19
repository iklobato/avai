"""LLM judging: the judge and cost estimation."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass

from .constants import (
    DEFAULT_JUDGE_BATCH,
    DEFAULT_JUDGE_MAX_PER_COLLECTOR,
    DEFAULT_JUDGE_MODEL,
    DEFAULT_PRICING,
    LOG,
    MODEL_PRICING,
)
from .enums import ThreatCategory, Verdict
from .llm import CompletionClient, CompletionRequest, StructuredCall
from .prompts import Prompts
from .runtime import Clock, Coerce


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


class LlmJudge(Judge):
    """Threat judge backed by an LLM through the injected completion client.
    Prompts are injected via the ``Prompts`` object.

    Structured output is enforced via the client's
    ``complete_structured`` (JSON-mode for litellm, tool_use for OAuth).
    Either way the caller receives a dict directly.
    """

    SCHEMA_NAME = "submit_judgments"
    TEMPERATURE = 0.0
    MAX_TOKENS = 4096

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
        client: CompletionClient,
        model: str = DEFAULT_JUDGE_MODEL,
        batch_size: int = DEFAULT_JUDGE_BATCH,
        max_per_collector: int = DEFAULT_JUDGE_MAX_PER_COLLECTOR,
    ):
        self.model = model
        # Clamp: batch_size 0 makes range() raise inside the _batches
        # generator (escapes the per-batch try); negative silently judges
        # nothing. Either way a bad --judge-batch-size must not break the cycle.
        self.batch_size = max(1, batch_size)
        self.max_per_collector = max_per_collector
        self._llm = StructuredCall(
            "judge",
            client,
            CompletionRequest(
                model=model,
                system=prompts.system,
                user=prompts.user_template,
                schema=self._judgment_schema(),
                schema_name=self.SCHEMA_NAME,
                max_tokens=self.MAX_TOKENS,
                temperature=self.TEMPERATURE,
            ),
        )

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
        parsed = self._llm.ask(
            collector=collector,
            hints=hints,
            entries=json.dumps(payload, ensure_ascii=False),
        )
        # Attribute the call's estimated cost evenly across the batch's
        # entries — one API call judges the whole batch, so each entry bears
        # an equal share.
        usage = getattr(self._llm.client, "last_usage", None)
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
                verdict=Coerce.enum(
                    str(item.get("verdict") or "").strip().lower(),
                    Verdict,
                    Verdict.UNKNOWN,
                ),
                category=Coerce.enum(
                    str(item.get("category") or "").strip().lower(),
                    ThreatCategory,
                    ThreatCategory.NONE,
                ),
                confidence=max(0.0, min(1.0, confidence)),
                reasoning=str(item.get("reasoning") or "")[:500],
                remediation=str(item.get("remediation") or "")[:2000],
                model=self.model,
                created_at=now,
                cost_usd=cost_usd,
            )
