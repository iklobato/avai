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
import os
from string import Template
from typing import Optional

from .constants import DEFAULT_NARRATIVE_MODEL, LOG
from .judge import HAS_LITELLM, CompletionClient, build_completion_client
from .prompts import Prompts


class MaliciousVerdictVerifier:
    """Independent skeptic pass over a single ``malicious`` finding."""

    SCHEMA_NAME = "submit_verification"

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
        model: str = DEFAULT_NARRATIVE_MODEL,
        temperature: float = 0.0,
        max_tokens: int = 512,
        client: Optional[CompletionClient] = None,
    ):
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._system = prompts.verifier_system
        self._user_template = Template(prompts.verifier_user_template)
        self._client = client or build_completion_client()
        self._schema = self._verification_schema()

    @property
    def auth_mode(self) -> str:
        return type(self._client).__name__

    def verify(self, finding: dict) -> Optional[dict]:
        """Return ``{"refuted": bool, "reasoning": str}`` or None on failure.
        Never raises — a verification failure must leave the original verdict
        untouched, not abort the cycle."""
        user = self._user_template.safe_substitute(
            finding=json.dumps(finding, ensure_ascii=False)
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
                "verifier failed error=%s msg=%s",
                type(exc).__name__,
                str(exc)[:200],
            )
            return None
        return {
            "refuted": bool(parsed.get("refuted")),
            "reasoning": str(parsed.get("reasoning") or "").strip()[:500],
        }


def build_verifier(args, prompts: Prompts) -> "Optional[MaliciousVerdictVerifier]":
    """Build the verifier when enabled and credentials exist. Returns None
    (verification disabled) otherwise — the same credential rule as the
    judge, since it needs an LLM client."""
    if getattr(args, "no_verify", False):
        return None
    if not prompts.verifier_system:
        LOG.warning("verifier prompt missing from prompts file; verification disabled")
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
        verifier = MaliciousVerdictVerifier(prompts=prompts, model=args.judge_model)
    except RuntimeError as exc:
        LOG.warning("MaliciousVerdictVerifier unavailable (%s); disabled", exc)
        return None
    LOG.info("verifier auth_mode=%s model=%s", verifier.auth_mode, verifier.model)
    return verifier
