"""Second-stage LLM that assesses YARA ruleset coverage for the host.

Reads the compiled ruleset summary (count / sources / per-category counts)
and a compact host profile (platform + inventory counts) and judges whether
the loaded rules adequately cover THIS host's threat surface — a posture, a
headline, gaps, and recommendations. Reuses the judge's completion client and
structured-output path, exactly like :class:`IncidentNarrator`.
"""

from __future__ import annotations

import json
from typing import Any

from .constants import DEFAULT_NARRATIVE_MODEL
from .enums import CoveragePosture
from .llm import CompletionRequest, LlmSession, StructuredCall
from .llm_replies import CoverageReply
from .prompts import Prompts


class YaraCoverageAssessor:
    """Second-stage LLM that reads the loaded YARA ruleset + a host profile
    and returns a structured coverage assessment."""

    SCHEMA_NAME = "submit_coverage"
    TEMPERATURE = 0.2
    MAX_TOKENS = 1024

    @classmethod
    def _posture_schema(cls) -> dict[str, Any]:
        return {
            "type": "string",
            "enum": [posture.value for posture in CoveragePosture],
        }

    @classmethod
    def _coverage_schema(cls) -> dict[str, Any]:
        item = {
            "type": "object",
            "properties": {
                "area": {"type": "string"},
                "action": {"type": "string"},
                "detail": {"type": "string"},
            },
        }
        return {
            "type": "object",
            "properties": {
                "posture": cls._posture_schema(),
                "headline": {"type": "string"},
                "summary": {"type": "string"},
                "gaps": {"type": "array", "items": item},
                "recommendations": {"type": "array", "items": item},
            },
            "required": ["posture", "headline", "summary", "gaps", "recommendations"],
        }

    def __init__(self, llm: StructuredCall) -> None:
        self._llm = llm

    @classmethod
    def create(
        cls, prompts: Prompts, session: LlmSession, model: str = DEFAULT_NARRATIVE_MODEL
    ) -> YaraCoverageAssessor:
        request = CompletionRequest(
            model=model,
            system=prompts.coverage_system,
            user=prompts.coverage_user_template,
            schema=cls._coverage_schema(),
            schema_name=cls.SCHEMA_NAME,
            max_tokens=cls.MAX_TOKENS,
            temperature=cls.TEMPERATURE,
        )
        return cls(StructuredCall("coverage assessor", session, request))

    @property
    def model(self) -> str:
        return self._llm.request.model

    def assess(
        self, ruleset: dict[str, Any], host: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Return ``{posture, headline, summary, gaps[], recommendations[]}``
        or None on failure or an empty ruleset."""
        if not ruleset or not ruleset.get("rules_loaded"):
            return None
        parsed = self._llm.ask_or_none(
            {
                "ruleset": json.dumps(ruleset, ensure_ascii=False),
                "host": json.dumps(host, ensure_ascii=False),
            }
        )
        if parsed is None:
            return None
        return CoverageReply.model_validate(parsed).assessment()
