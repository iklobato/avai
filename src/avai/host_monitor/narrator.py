"""Second-stage LLM that turns active findings into an incident digest."""

from __future__ import annotations

import json
from typing import Optional

from .constants import DEFAULT_NARRATIVE_MODEL
from .llm import CompletionClient, CompletionRequest, StructuredCall
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
        client: CompletionClient,
        model: str = DEFAULT_NARRATIVE_MODEL,
    ):
        self.model = model
        self._llm = StructuredCall(
            "narrator",
            client,
            CompletionRequest(
                model=model,
                system=prompts.narrator_system,
                user=prompts.narrator_user_template,
                schema=self._narrative_schema(),
                schema_name=self.SCHEMA_NAME,
                max_tokens=self.MAX_TOKENS,
                temperature=self.TEMPERATURE,
            ),
        )

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
        parsed = self._llm.ask_or_none(
            count=len(findings),
            findings=json.dumps(findings, ensure_ascii=False),
        )
        if parsed is None:
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
