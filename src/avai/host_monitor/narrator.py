"""Second-stage LLM that turns active findings into an incident digest."""

from __future__ import annotations

import json
import os
from string import Template
from typing import Optional

from .constants import DEFAULT_NARRATIVE_MODEL, LOG
from .judge import HAS_LITELLM, CompletionClient, build_completion_client
from .prompts import Prompts


class IncidentNarrator:
    """Second-stage LLM that reads the host's currently-active non-benign
    findings (already judged) and synthesises them into one incident
    digest: a headline, a severity, an attack-story narrative, and
    prioritised recommended actions. Reuses the judge's completion client
    and structured-output path."""

    SCHEMA_NAME = "submit_incident"
    SEVERITIES = ("informational", "low", "medium", "high", "critical")
    PRIORITIES = ("immediate", "high", "medium", "low")
    # Bound the prompt: a host with hundreds of active findings would
    # otherwise produce a user message that can blow the context window and
    # fail the digest every cycle. Keep the most severe/confident findings.
    MAX_FINDINGS = 40
    _VERDICT_RANK = {"malicious": 2, "suspicious": 1}

    @classmethod
    def _narrative_schema(cls) -> dict:
        return {
            "type": "object",
            "properties": {
                "headline": {"type": "string"},
                "severity": {"type": "string", "enum": list(cls.SEVERITIES)},
                "summary": {"type": "string"},
                "timeline": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "time": {"type": "string"},
                            "title": {"type": "string"},
                            "category": {"type": "string"},
                            "detail": {"type": "string"},
                        },
                        "required": ["title"],
                    },
                },
                "actions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "priority": {
                                "type": "string",
                                "enum": list(cls.PRIORITIES),
                            },
                            "title": {"type": "string"},
                            "command": {"type": "string"},
                            "detail": {"type": "string"},
                        },
                        "required": ["title"],
                    },
                },
            },
            "required": ["headline", "severity", "summary", "timeline", "actions"],
        }

    def __init__(
        self,
        prompts: Prompts,
        model: str = DEFAULT_NARRATIVE_MODEL,
        temperature: float = 0.3,
        max_tokens: int = 2048,
        client: Optional[CompletionClient] = None,
    ):
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._system = prompts.narrator_system
        self._user_template = Template(prompts.narrator_user_template)
        self._client = client or build_completion_client()
        self._schema = self._narrative_schema()

    @property
    def auth_mode(self) -> str:
        return type(self._client).__name__

    def _cap(self, findings: list[dict]) -> list[dict]:
        """Trim to MAX_FINDINGS, keeping the most severe/confident, then
        restore the original (timeline) order so the digest still reads as
        a sequence."""
        if len(findings) <= self.MAX_FINDINGS:
            return findings
        ranked = sorted(
            enumerate(findings),
            key=lambda it: (
                self._VERDICT_RANK.get(str(it[1].get("verdict")), 0),
                it[1].get("confidence") or 0.0,
            ),
            reverse=True,
        )[: self.MAX_FINDINGS]
        return [f for _, f in sorted(ranked, key=lambda it: it[0])]

    def narrate(self, findings: list[dict]) -> Optional[dict]:
        """Return a structured digest
        ``{headline, severity, summary, timeline[], actions[]}`` or None on
        failure/empty input. Never raises — a digest failure must not abort
        the cycle."""
        if not findings:
            return None
        findings = self._cap(findings)
        user = self._user_template.safe_substitute(
            count=len(findings),
            findings=json.dumps(findings, ensure_ascii=False),
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
                "narrator failed error=%s msg=%s",
                type(exc).__name__,
                str(exc)[:200],
            )
            return None
        severity = str(parsed.get("severity") or "").lower()
        if severity not in self.SEVERITIES:
            severity = "low"
        headline = str(parsed.get("headline") or "").strip()[:200]
        summary = str(parsed.get("summary") or "").strip()[:2000]
        timeline = self._clean_timeline(parsed.get("timeline"))
        actions = self._clean_actions(parsed.get("actions"))
        if not headline or not (summary or timeline):
            return None
        return {
            "headline": headline,
            "severity": severity,
            "summary": summary,
            "timeline": timeline,
            "actions": actions,
        }

    def _clean_timeline(self, raw) -> list[dict]:
        out: list[dict] = []
        for ev in raw or []:
            if not isinstance(ev, dict):
                continue
            title = str(ev.get("title") or "").strip()
            if not title:
                continue
            out.append(
                {
                    "time": str(ev.get("time") or "").strip()[:40],
                    "title": title[:200],
                    "category": str(ev.get("category") or "").strip().lower()[:40],
                    "detail": str(ev.get("detail") or "").strip()[:500],
                }
            )
        return out[:30]

    def _clean_actions(self, raw) -> list[dict]:
        out: list[dict] = []
        for a in raw or []:
            if not isinstance(a, dict):
                continue
            title = str(a.get("title") or "").strip()
            if not title:
                continue
            priority = str(a.get("priority") or "").strip().lower()
            if priority not in self.PRIORITIES:
                priority = "medium"
            out.append(
                {
                    "priority": priority,
                    "title": title[:200],
                    "command": str(a.get("command") or "").strip()[:1000],
                    "detail": str(a.get("detail") or "").strip()[:600],
                }
            )
        return out[:15]


def build_narrator(args, prompts: Prompts) -> "Optional[IncidentNarrator]":
    """Build the incident narrator when enabled and credentials exist.
    Returns None (digest disabled) otherwise — the same credential rule as
    the judge, since a digest is only meaningful when judging runs."""
    if args.no_narrative or args.no_judge:
        return None
    if not prompts.narrator_system:
        LOG.warning("narrator prompt missing from prompts file; digest disabled")
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
        narrator = IncidentNarrator(prompts=prompts, model=args.narrative_model)
    except RuntimeError as exc:
        LOG.warning("IncidentNarrator unavailable (%s); digest disabled", exc)
        return None
    LOG.info("narrator auth_mode=%s model=%s", narrator.auth_mode, narrator.model)
    return narrator
