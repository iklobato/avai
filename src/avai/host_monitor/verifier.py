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
from typing import Optional

from .constants import DEFAULT_NARRATIVE_MODEL
from .llm import CompletionClient, CompletionRequest, StructuredCall
from .prompts import Prompts


class MaliciousVerdictVerifier:
    """Independent skeptic pass over a single ``malicious`` finding."""

    SCHEMA_NAME = "submit_verification"
    TEMPERATURE = 0.0
    MAX_TOKENS = 512

    @classmethod
    def _verification_schema(cls) -> dict:
        return {
            "type": "object",
            "properties": {
                "refuted": {"type": "boolean"},
                "reasoning": {"type": "string"},
            },
            "required": ["refuted", "reasoning"],
        }

    def __init__(
        self,
        prompts: Prompts,
        client: CompletionClient,
        model: str = DEFAULT_NARRATIVE_MODEL,
    ):
        self.model = model
        self._llm = StructuredCall(
            "verifier",
            client,
            CompletionRequest(
                model=model,
                system=prompts.verifier_system,
                user=prompts.verifier_user_template,
                schema=self._verification_schema(),
                schema_name=self.SCHEMA_NAME,
                max_tokens=self.MAX_TOKENS,
                temperature=self.TEMPERATURE,
            ),
        )

    def verify(self, finding: dict) -> Optional[dict]:
        """Return ``{"refuted": bool, "reasoning": str}`` or None on failure.
        Never raises — a verification failure must leave the original verdict
        untouched, not abort the cycle."""
        parsed = self._llm.ask_or_none(finding=json.dumps(finding, ensure_ascii=False))
        if parsed is None:
            return None
        return {
            "refuted": bool(parsed.get("refuted")),
            "reasoning": str(parsed.get("reasoning") or "").strip()[:500],
        }
