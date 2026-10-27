"""Second-opinion LLM that adversarially checks ``malicious`` verdicts.

The first-pass judge decides in one shot. A false ``malicious`` is the most
costly mistake (it cries wolf and gets the tool ignored), so every malicious
verdict is re-examined by an independent skeptic prompted to *refute* it. A
refuted verdict is downgraded to ``suspicious`` rather than dropped — still
worth review, just not asserted as an active threat. Reuses the judge's
completion client and structured-output path, like the other second stages.
"""

from __future__ import annotations

import json
from typing import Any

from .constants import DEFAULT_NARRATIVE_MODEL
from .llm import CompletionRequest, LlmSession, StructuredCall
from .llm_replies import VerifierReply
from .prompts import Prompts


class MaliciousVerdictVerifier:
    """Independent skeptic pass over a single ``malicious`` finding."""

    SCHEMA_NAME = "submit_verification"
    TEMPERATURE = 0.0
    MAX_TOKENS = 512

    @classmethod
    def _verification_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "refuted": {"type": "boolean"},
                "reasoning": {"type": "string"},
            },
            "required": ["refuted", "reasoning"],
        }

    def __init__(self, llm: StructuredCall) -> None:
        self._llm = llm

    @classmethod
    def create(
        cls, prompts: Prompts, session: LlmSession, model: str = DEFAULT_NARRATIVE_MODEL
    ) -> MaliciousVerdictVerifier:
        request = CompletionRequest(
            model=model,
            system=prompts.verifier_system,
            user=prompts.verifier_user_template,
            schema=cls._verification_schema(),
            schema_name=cls.SCHEMA_NAME,
            max_tokens=cls.MAX_TOKENS,
            temperature=cls.TEMPERATURE,
        )
        return cls(StructuredCall("verifier", session, request))

    @property
    def model(self) -> str:
        return self._llm.request.model

    def verify(self, finding: dict[str, Any]) -> dict[str, Any] | None:
        """Return ``{"refuted": bool, "reasoning": str}`` or None on failure.
        A verification failure leaves the original verdict untouched rather
        than aborting the cycle."""
        parsed = self._llm.ask_or_none(
            {"finding": json.dumps(finding, ensure_ascii=False)}
        )
        if parsed is None:
            return None
        return VerifierReply.model_validate(parsed).fields()
