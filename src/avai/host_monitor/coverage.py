"""Second-stage LLM that assesses YARA ruleset coverage for the host.

Reads the compiled ruleset summary (count / sources / per-category counts)
and a compact host profile (platform + inventory counts) and judges whether
the loaded rules adequately cover THIS host's threat surface — a posture, a
headline, gaps, and recommendations. Reuses the judge's completion client and
structured-output path, exactly like :class:`IncidentNarrator`.
"""

from __future__ import annotations

import json
import os
from string import Template
from typing import Optional

from .constants import DEFAULT_NARRATIVE_MODEL, LOG
from .judge import HAS_LITELLM, CompletionClient, build_completion_client
from .prompts import Prompts


class YaraCoverageAssessor:
    """Second-stage LLM that reads the loaded YARA ruleset + a host profile
    and returns a structured coverage assessment."""

    SCHEMA_NAME = "submit_coverage"
    POSTURES = ("well_covered", "partial", "thin")

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
        model: str = DEFAULT_NARRATIVE_MODEL,
        temperature: float = 0.2,
        max_tokens: int = 1024,
        client: Optional[CompletionClient] = None,
    ):
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._system = prompts.coverage_system
        self._user_template = Template(prompts.coverage_user_template)
        self._client = client or build_completion_client()
        self._schema = self._coverage_schema()

    @property
    def auth_mode(self) -> str:
        return type(self._client).__name__

    def assess(self, ruleset: dict, host: dict) -> Optional[dict]:
        """Return ``{posture, headline, summary, gaps[], recommendations[]}``
        or None on failure/empty ruleset. Never raises — a coverage-assessment
        failure must not abort the cycle."""
        if not ruleset or not ruleset.get("rules_loaded"):
            return None
        user = self._user_template.safe_substitute(
            ruleset=json.dumps(ruleset, ensure_ascii=False),
            host=json.dumps(host, ensure_ascii=False),
        )
        try:
            parsed = self._client.complete_structured(
                model=self.model,
                system=self._system,
                user=user,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                schema=self._schema,
                schema_name=self.SCHEMA_NAME,
            )
        except Exception as exc:
            LOG.warning(
                "coverage assessor failed error=%s msg=%s",
                type(exc).__name__,
                str(exc)[:200],
            )
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


def build_coverage_assessor(args, prompts: Prompts) -> "Optional[YaraCoverageAssessor]":
    """Build the coverage assessor when enabled and credentials exist.
    Returns None (assessment disabled) otherwise — the same credential rule as
    the judge/narrator, since it needs an LLM client."""
    if getattr(args, "no_coverage", False):
        return None
    if not prompts.coverage_system:
        LOG.warning("coverage prompt missing from prompts file; assessment disabled")
        return None
    has_oauth = bool(os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"))
    has_api_key = bool(
        os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY")
    )
    if not has_oauth and not has_api_key:
        return None
    if not has_oauth and not HAS_LITELLM:
        return None
    try:
        assessor = YaraCoverageAssessor(prompts=prompts, model=args.narrative_model)
    except RuntimeError as exc:
        LOG.warning("YaraCoverageAssessor unavailable (%s); assessment disabled", exc)
        return None
    LOG.info("coverage auth_mode=%s model=%s", assessor.auth_mode, assessor.model)
    return assessor
