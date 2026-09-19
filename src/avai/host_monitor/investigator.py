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
from typing import Optional

from .constants import DEFAULT_JUDGE_MODEL
from .enums import ThreatCategory, Verdict
from .llm import CompletionClient, CompletionRequest, StructuredCall
from .prompts import Prompts
from .runtime import Coerce


class UnknownFindingInvestigator:
    """Re-judge a single ``unknown`` finding given a richer context bundle."""

    SCHEMA_NAME = "submit_investigation"
    TEMPERATURE = 0.0
    MAX_TOKENS = 1024

    @classmethod
    def _investigation_schema(cls) -> dict:
        return {
            "type": "object",
            "properties": {
                "verdict": {"type": "string", "enum": [str(v) for v in Verdict]},
                "category": {
                    "type": "string",
                    "enum": [str(c) for c in ThreatCategory],
                },
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "reasoning": {"type": "string"},
                "remediation": {"type": "string"},
            },
            "required": [
                "verdict",
                "category",
                "confidence",
                "reasoning",
                "remediation",
            ],
        }

    def __init__(
        self,
        prompts: Prompts,
        client: CompletionClient,
        model: str = DEFAULT_JUDGE_MODEL,
    ):
        self.model = model
        self._llm = StructuredCall(
            "investigator",
            client,
            CompletionRequest(
                model=model,
                system=prompts.investigator_system,
                user=prompts.investigator_user_template,
                schema=self._investigation_schema(),
                schema_name=self.SCHEMA_NAME,
                max_tokens=self.MAX_TOKENS,
                temperature=self.TEMPERATURE,
            ),
        )

    def investigate(self, collector: str, finding: dict) -> Optional[dict]:
        """Return a fresh judgment
        ``{verdict, category, confidence, reasoning, remediation}`` (verdict and
        category as enums) or None on failure. Never raises."""
        parsed = self._llm.ask_or_none(
            collector=collector,
            finding=json.dumps(finding, ensure_ascii=False, default=str),
        )
        if parsed is None:
            return None
        try:
            confidence = float(parsed.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        return {
            "verdict": Coerce.enum(
                str(parsed.get("verdict") or "").strip().lower(),
                Verdict,
                Verdict.UNKNOWN,
            ),
            "category": Coerce.enum(
                str(parsed.get("category") or "").strip().lower(),
                ThreatCategory,
                ThreatCategory.NONE,
            ),
            "confidence": max(0.0, min(1.0, confidence)),
            "reasoning": str(parsed.get("reasoning") or "")[:500],
            "remediation": str(parsed.get("remediation") or "")[:2000],
        }
