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
import os
from string import Template
from typing import Optional

from .constants import DEFAULT_JUDGE_MODEL, LOG
from .enums import ThreatCategory, Verdict
from .judge import HAS_LITELLM, CompletionClient, build_completion_client
from .prompts import Prompts
from .runtime import Coerce


class UnknownFindingInvestigator:
    """Re-judge a single ``unknown`` finding given a richer context bundle."""

    SCHEMA_NAME = "submit_investigation"

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
        model: str = DEFAULT_JUDGE_MODEL,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        client: Optional[CompletionClient] = None,
    ):
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._system = prompts.investigator_system
        self._user_template = Template(prompts.investigator_user_template)
        self._client = client or build_completion_client()
        self._schema = self._investigation_schema()

    @property
    def auth_mode(self) -> str:
        return type(self._client).__name__

    def investigate(self, collector: str, finding: dict) -> Optional[dict]:
        """Return a fresh judgment
        ``{verdict, category, confidence, reasoning, remediation}`` (verdict and
        category as enums) or None on failure. Never raises."""
        user = self._user_template.safe_substitute(
            collector=collector,
            finding=json.dumps(finding, ensure_ascii=False, default=str),
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
                "investigator failed error=%s msg=%s",
                type(exc).__name__,
                str(exc)[:200],
            )
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


def build_investigator(
    args, prompts: Prompts
) -> "Optional[UnknownFindingInvestigator]":
    """Build the investigator when enabled and credentials exist. Returns None
    (investigation disabled) otherwise — the same credential rule as the
    judge, since it needs an LLM client."""
    if getattr(args, "no_investigate", False):
        return None
    if not prompts.investigator_system:
        LOG.warning("investigator prompt missing from prompts file; disabled")
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
        investigator = UnknownFindingInvestigator(
            prompts=prompts, model=args.judge_model
        )
    except RuntimeError as exc:
        LOG.warning("UnknownFindingInvestigator unavailable (%s); disabled", exc)
        return None
    LOG.info(
        "investigator auth_mode=%s model=%s",
        investigator.auth_mode,
        investigator.model,
    )
    return investigator
