"""Second-stage LLM that assesses YARA ruleset coverage for the host.

Reads the compiled ruleset summary (count / sources / per-category counts)
and a compact host profile (platform + inventory counts) and judges whether
the loaded rules adequately cover THIS host's threat surface — a posture, a
headline, gaps, and recommendations. Reuses the judge's completion client and
structured-output path, exactly like :class:`IncidentNarrator`.
"""

from __future__ import annotations

import json
from typing import Optional

from .constants import DEFAULT_NARRATIVE_MODEL
from .llm import CompletionClient, CompletionRequest, StructuredCall
from .prompts import Prompts


class YaraCoverageAssessor:
    """Second-stage LLM that reads the loaded YARA ruleset + a host profile
    and returns a structured coverage assessment."""

    SCHEMA_NAME = "submit_coverage"
    POSTURES = ("well_covered", "partial", "thin")
    TEMPERATURE = 0.2
    MAX_TOKENS = 1024

    @classmethod
    def _coverage_schema(cls) -> dict:
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
                "posture": {"type": "string", "enum": list(cls.POSTURES)},
                "headline": {"type": "string"},
                "summary": {"type": "string"},
                "gaps": {"type": "array", "items": item},
                "recommendations": {"type": "array", "items": item},
            },
            "required": ["posture", "headline", "summary", "gaps", "recommendations"],
        }

    def __init__(
        self,
        prompts: Prompts,
        client: CompletionClient,
        model: str = DEFAULT_NARRATIVE_MODEL,
    ):
        self.model = model
        self._llm = StructuredCall(
            "coverage assessor",
            client,
            CompletionRequest(
                model=model,
                system=prompts.coverage_system,
                user=prompts.coverage_user_template,
                schema=self._coverage_schema(),
                schema_name=self.SCHEMA_NAME,
                max_tokens=self.MAX_TOKENS,
                temperature=self.TEMPERATURE,
            ),
        )

    def assess(self, ruleset: dict, host: dict) -> Optional[dict]:
        """Return ``{posture, headline, summary, gaps[], recommendations[]}``
        or None on failure/empty ruleset. Never raises — a coverage-assessment
        failure must not abort the cycle."""
        if not ruleset or not ruleset.get("rules_loaded"):
            return None
        parsed = self._llm.ask_or_none(
            ruleset=json.dumps(ruleset, ensure_ascii=False),
            host=json.dumps(host, ensure_ascii=False),
        )
        if parsed is None:
            return None
        posture = str(parsed.get("posture") or "").lower()
        if posture not in self.POSTURES:
            posture = "partial"
        headline = str(parsed.get("headline") or "").strip()[:200]
        summary = str(parsed.get("summary") or "").strip()[:2000]
        gaps = self._clean_items(parsed.get("gaps"), "area")
        recommendations = self._clean_items(parsed.get("recommendations"), "action")
        if not headline or not (summary or gaps):
            return None
        return {
            "posture": posture,
            "headline": headline,
            "summary": summary,
            "gaps": gaps,
            "recommendations": recommendations,
        }

    @staticmethod
    def _clean_items(raw, label_key: str) -> list[dict]:
        """Normalise a gaps/recommendations array: keep the entries whose
        label field (``area`` or ``action``) is non-empty, trim the rest."""
        out: list[dict] = []
        for it in raw or []:
            if not isinstance(it, dict):
                continue
            label = str(it.get(label_key) or "").strip()
            if not label:
                continue
            out.append(
                {
                    label_key: label[:100],
                    "detail": str(it.get("detail") or "").strip()[:300],
                }
            )
        return out[:12]
