"""Deep second pass that re-judges findings the first pass left ``unknown``.

The per-collector judge decides in one shot from a bounded context. When it
returns ``unknown`` (insufficient information), this stage re-judges the
artifact with a RICHER, deliberately-gathered bundle — full-history behaviour
correlation, all threat-intel evidence, and the host's other active findings —
so "I can't tell" turns into a committed verdict more often.

This is the bounded form of an investigator: it gathers a fixed deeper context
and re-judges once. A fully agentic version (the LLM choosing which tools to
call over multiple turns) would need a multi-turn client abstraction the
codebase doesn't have yet; that's a deliberate follow-up.
"""

from __future__ import annotations

import json
from typing import Any

from .constants import DEFAULT_JUDGE_MODEL
from .enums import ThreatCategory, Verdict
from .llm import CompletionRequest, LlmSession, ParsedReply, StructuredCall
from .prompts import Prompts
from .runtime import Coerce


class UnknownFindingInvestigator:
    """Re-judge a single ``unknown`` finding given a richer context bundle."""

    SCHEMA_NAME = "submit_investigation"
    TEMPERATURE = 0.0
    MAX_TOKENS = 1024

    REASONING_CHARS = 500
    REMEDIATION_CHARS = 2000
    REQUIRED = ("verdict", "category", "confidence", "reasoning", "remediation")

    @classmethod
    def _investigation_schema(cls) -> dict[str, Any]:
        verdicts = [str(verdict) for verdict in Verdict]
        categories = [str(category) for category in ThreatCategory]
        return {
            "type": "object",
            "properties": {
                "verdict": {"type": "string", "enum": verdicts},
                "category": {"type": "string", "enum": categories},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "reasoning": {"type": "string"},
                "remediation": {"type": "string"},
            },
            "required": list(cls.REQUIRED),
        }

    def __init__(self, llm: StructuredCall) -> None:
        self._llm = llm

    @classmethod
    def create(
        cls, prompts: Prompts, session: LlmSession, model: str = DEFAULT_JUDGE_MODEL
    ) -> UnknownFindingInvestigator:
        request = CompletionRequest(
            model=model,
            system=prompts.investigator_system,
            user=prompts.investigator_user_template,
            schema=cls._investigation_schema(),
            schema_name=cls.SCHEMA_NAME,
            max_tokens=cls.MAX_TOKENS,
            temperature=cls.TEMPERATURE,
        )
        return cls(StructuredCall("investigator", session, request))

    @property
    def model(self) -> str:
        return self._llm.request.model

    def investigate(
        self, collector: str, finding: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Return a fresh judgment
        ``{verdict, category, confidence, reasoning, remediation}`` (verdict and
        category as enums) or None when the call fails."""
        finding_json = json.dumps(finding, ensure_ascii=False, default=str)
        parsed = self._llm.ask_or_none(
            {"collector": collector, "finding": finding_json}
        )
        return None if parsed is None else self._judgment(ParsedReply(parsed))

    def _judgment(self, reply: ParsedReply) -> dict[str, Any]:
        coerce = Coerce()
        return {
            "verdict": coerce.enum(reply.keyword("verdict"), Verdict, Verdict.UNKNOWN),
            "category": coerce.enum(
                reply.keyword("category"), ThreatCategory, ThreatCategory.NONE
            ),
            "confidence": reply.fraction("confidence"),
            "reasoning": reply.raw_text("reasoning", self.REASONING_CHARS),
            "remediation": reply.raw_text("remediation", self.REMEDIATION_CHARS),
        }
