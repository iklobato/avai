"""Second-stage LLM that turns active findings into an incident digest."""

from __future__ import annotations

import json
from typing import Any

from .constants import DEFAULT_NARRATIVE_MODEL
from .enums import ActionPriority, IncidentSeverity, Verdict
from .llm import CompletionRequest, LlmSession, StructuredCall
from .llm_replies import NarrativeReply
from .prompts import Prompts


class IncidentNarrator:
    """Second-stage LLM that reads the host's currently-active non-benign
    findings (already judged) and synthesises them into one incident
    digest: a headline, a severity, an attack-story narrative, and
    prioritised recommended actions. Reuses the judge's completion client
    and structured-output path."""

    SCHEMA_NAME = "submit_incident"
    TEMPERATURE = 0.3
    MAX_TOKENS = 2048
    # Bound the prompt: a host with hundreds of active findings would
    # otherwise produce a user message that can blow the context window and
    # fail the digest every cycle. Keep the most severe/confident findings.
    MAX_FINDINGS = 40
    _VERDICT_RANK = {Verdict.MALICIOUS: 2, Verdict.SUSPICIOUS: 1}

    @classmethod
    def _narrative_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "headline": {"type": "string"},
                "severity": {
                    "type": "string",
                    "enum": [severity.value for severity in IncidentSeverity],
                },
                "summary": {"type": "string"},
                "timeline": {"type": "array", "items": cls._event_schema()},
                "actions": {"type": "array", "items": cls._action_schema()},
            },
            "required": ["headline", "severity", "summary", "timeline", "actions"],
        }

    @classmethod
    def _event_schema(cls) -> dict[str, Any]:
        fields = ("time", "title", "category", "detail")
        return {
            "type": "object",
            "properties": {name: {"type": "string"} for name in fields},
            "required": ["title"],
        }

    @classmethod
    def _action_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "priority": {
                    "type": "string",
                    "enum": [priority.value for priority in ActionPriority],
                },
                "title": {"type": "string"},
                "command": {"type": "string"},
                "detail": {"type": "string"},
            },
            "required": ["title"],
        }

    def __init__(self, llm: StructuredCall) -> None:
        self._llm = llm

    @classmethod
    def create(
        cls, prompts: Prompts, session: LlmSession, model: str = DEFAULT_NARRATIVE_MODEL
    ) -> IncidentNarrator:
        request = CompletionRequest(
            model=model,
            system=prompts.narrator_system,
            user=prompts.narrator_user_template,
            schema=cls._narrative_schema(),
            schema_name=cls.SCHEMA_NAME,
            max_tokens=cls.MAX_TOKENS,
            temperature=cls.TEMPERATURE,
        )
        return cls(StructuredCall("narrator", session, request))

    @property
    def model(self) -> str:
        return self._llm.request.model

    def narrate(self, findings: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Return a structured digest
        ``{headline, severity, summary, timeline[], actions[]}`` or None on
        failure or empty input."""
        if not findings:
            return None
        kept = self._cap(findings)
        parsed = self._llm.ask_or_none(
            {
                "count": str(len(kept)),
                "findings": json.dumps(kept, ensure_ascii=False),
            }
        )
        if parsed is None:
            return None
        return NarrativeReply.model_validate(parsed).digest()

    def _cap(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Trim to MAX_FINDINGS, keeping the most severe/confident, then
        restore the original (timeline) order so the digest still reads as
        a sequence."""
        if len(findings) <= self.MAX_FINDINGS:
            return findings
        positions = sorted(
            range(len(findings)),
            key=lambda index: self._severity_key(findings[index]),
            reverse=True,
        )[: self.MAX_FINDINGS]
        return [findings[index] for index in sorted(positions)]

    def _severity_key(self, finding: dict[str, Any]) -> tuple[int, float]:
        rank = self._VERDICT_RANK.get(str(finding.get("verdict")), 0)
        return rank, finding.get("confidence") or 0.0
