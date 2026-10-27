"""Contracts for the structured replies the LLM stages get back.

A model may leave a field out, send it empty or send the wrong type; the
stage must still get a usable value, as it did with the old hand-written
reader. Every field therefore has a default and a ``mode="before"``
validator that turns a bad value into that default instead of failing.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, field_validator

from .enums import (
    ActionPriority,
    CoveragePosture,
    IncidentSeverity,
    ThreatCategory,
    Verdict,
)
from .runtime import Coerce


class ReplyValues:
    """The defensive conversions every reply model shares."""

    def text(self, value: object, limit: int) -> str:
        """Stripped text cut to ``limit``; missing or empty becomes ""."""
        return str(value or "").strip()[:limit]

    def raw_text(self, value: object, limit: int) -> str:
        """Text cut to ``limit`` but not stripped."""
        return str(value or "")[:limit]

    def keyword(self, value: object) -> str:
        return str(value or "").strip().lower()

    def choice(self, value: object, fallback: StrEnum) -> str:
        """The value when it names a member of ``fallback``'s enum, else
        ``fallback``'s value."""
        keyword = self.keyword(value)
        return keyword if keyword in tuple(type(fallback)) else fallback.value

    def labelled(self, value: object, label_key: str) -> list[dict[str, Any]]:
        """The objects of an array field whose ``label_key`` is non-empty;
        anything that is not a list gives no entries."""
        items = value if isinstance(value, list) else []
        objects = [item for item in items if isinstance(item, dict)]
        return [item for item in objects if self.text(item.get(label_key), 1)]

    def fraction(self, value: object) -> float:
        """A number clamped to ``[0, 1]``; 0.0 when absent or not numeric."""
        try:
            number = float(value or 0.0)
        except (TypeError, ValueError):
            return 0.0
        return max(0.0, min(1.0, number))


class VerifierReply(BaseModel):
    """The skeptic's answer on one malicious verdict."""

    model_config = ConfigDict(frozen=True)
    REASONING_CHARS: ClassVar[int] = 500

    refuted: bool = False
    reasoning: str = ""

    @field_validator("refuted", mode="before")
    @classmethod
    def _truthy(cls, value: object) -> bool:
        return bool(value)

    @field_validator("reasoning", mode="before")
    @classmethod
    def _reasoning(cls, value: object) -> str:
        return ReplyValues().text(value, cls.REASONING_CHARS)

    def fields(self) -> dict[str, Any]:
        return {"refuted": self.refuted, "reasoning": self.reasoning}


class JudgmentReply(BaseModel):
    """One verdict on one finding, from the judge or the investigator."""

    model_config = ConfigDict(frozen=True)
    REASONING_CHARS: ClassVar[int] = 500
    REMEDIATION_CHARS: ClassVar[int] = 2000

    verdict: Verdict = Verdict.UNKNOWN
    category: ThreatCategory = ThreatCategory.NONE
    confidence: float = 0.0
    reasoning: str = ""
    remediation: str = ""

    @field_validator("verdict", mode="before")
    @classmethod
    def _verdict(cls, value: object) -> Verdict:
        return Coerce().enum(ReplyValues().keyword(value), Verdict, Verdict.UNKNOWN)

    @field_validator("category", mode="before")
    @classmethod
    def _category(cls, value: object) -> ThreatCategory:
        keyword = ReplyValues().keyword(value)
        return Coerce().enum(keyword, ThreatCategory, ThreatCategory.NONE)

    @field_validator("confidence", mode="before")
    @classmethod
    def _confidence(cls, value: object) -> float:
        return ReplyValues().fraction(value)

    @field_validator("reasoning", mode="before")
    @classmethod
    def _reasoning(cls, value: object) -> str:
        return ReplyValues().raw_text(value, cls.REASONING_CHARS)

    @field_validator("remediation", mode="before")
    @classmethod
    def _remediation(cls, value: object) -> str:
        return ReplyValues().raw_text(value, cls.REMEDIATION_CHARS)

    def fields(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "category": self.category,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "remediation": self.remediation,
        }


class CoverageGap(BaseModel):
    model_config = ConfigDict(frozen=True)
    LABEL_CHARS: ClassVar[int] = 100
    DETAIL_CHARS: ClassVar[int] = 300

    area: str = ""
    detail: str = ""

    @field_validator("area", mode="before")
    @classmethod
    def _area(cls, value: object) -> str:
        return ReplyValues().text(value, cls.LABEL_CHARS)

    @field_validator("detail", mode="before")
    @classmethod
    def _detail(cls, value: object) -> str:
        return ReplyValues().text(value, cls.DETAIL_CHARS)


class CoverageAction(BaseModel):
    model_config = ConfigDict(frozen=True)
    LABEL_CHARS: ClassVar[int] = 100
    DETAIL_CHARS: ClassVar[int] = 300

    action: str = ""
    detail: str = ""

    @field_validator("action", mode="before")
    @classmethod
    def _action(cls, value: object) -> str:
        return ReplyValues().text(value, cls.LABEL_CHARS)

    @field_validator("detail", mode="before")
    @classmethod
    def _detail(cls, value: object) -> str:
        return ReplyValues().text(value, cls.DETAIL_CHARS)


class CoverageReply(BaseModel):
    """The YARA coverage assessment."""

    model_config = ConfigDict(frozen=True)
    HEADLINE_CHARS: ClassVar[int] = 200
    SUMMARY_CHARS: ClassVar[int] = 2000
    MAX_ITEMS: ClassVar[int] = 12

    posture: str = CoveragePosture.PARTIAL.value
    headline: str = ""
    summary: str = ""
    gaps: list[CoverageGap] = []
    recommendations: list[CoverageAction] = []

    @field_validator("posture", mode="before")
    @classmethod
    def _posture(cls, value: object) -> str:
        return ReplyValues().choice(value, CoveragePosture.PARTIAL)

    @field_validator("headline", mode="before")
    @classmethod
    def _headline(cls, value: object) -> str:
        return ReplyValues().text(value, cls.HEADLINE_CHARS)

    @field_validator("summary", mode="before")
    @classmethod
    def _summary(cls, value: object) -> str:
        return ReplyValues().text(value, cls.SUMMARY_CHARS)

    @field_validator("gaps", mode="before")
    @classmethod
    def _gap_entries(cls, value: object) -> list[dict[str, Any]]:
        return ReplyValues().labelled(value, "area")[: cls.MAX_ITEMS]

    @field_validator("recommendations", mode="before")
    @classmethod
    def _action_entries(cls, value: object) -> list[dict[str, Any]]:
        return ReplyValues().labelled(value, "action")[: cls.MAX_ITEMS]

    def assessment(self) -> dict[str, Any] | None:
        """None when the reply says nothing usable (no headline, or neither
        a summary nor a gap)."""
        if not self.headline or not (self.summary or self.gaps):
            return None
        return {
            "posture": self.posture,
            "headline": self.headline,
            "summary": self.summary,
            "gaps": [gap.model_dump() for gap in self.gaps],
            "recommendations": [item.model_dump() for item in self.recommendations],
        }


class TimelineEvent(BaseModel):
    model_config = ConfigDict(frozen=True)
    TIME_CHARS: ClassVar[int] = 40
    TITLE_CHARS: ClassVar[int] = 200
    CATEGORY_CHARS: ClassVar[int] = 40
    DETAIL_CHARS: ClassVar[int] = 500

    time: str = ""
    title: str = ""
    category: str = ""
    detail: str = ""

    @field_validator("time", mode="before")
    @classmethod
    def _time(cls, value: object) -> str:
        return ReplyValues().text(value, cls.TIME_CHARS)

    @field_validator("title", mode="before")
    @classmethod
    def _title(cls, value: object) -> str:
        return ReplyValues().text(value, cls.TITLE_CHARS)

    @field_validator("category", mode="before")
    @classmethod
    def _category(cls, value: object) -> str:
        return ReplyValues().text(value, cls.CATEGORY_CHARS).lower()

    @field_validator("detail", mode="before")
    @classmethod
    def _detail(cls, value: object) -> str:
        return ReplyValues().text(value, cls.DETAIL_CHARS)


class NarrativeAction(BaseModel):
    model_config = ConfigDict(frozen=True)
    TITLE_CHARS: ClassVar[int] = 200
    COMMAND_CHARS: ClassVar[int] = 1000
    DETAIL_CHARS: ClassVar[int] = 600

    priority: str = ActionPriority.MEDIUM.value
    title: str = ""
    command: str = ""
    detail: str = ""

    @field_validator("priority", mode="before")
    @classmethod
    def _priority(cls, value: object) -> str:
        return ReplyValues().choice(value, ActionPriority.MEDIUM)

    @field_validator("title", mode="before")
    @classmethod
    def _title(cls, value: object) -> str:
        return ReplyValues().text(value, cls.TITLE_CHARS)

    @field_validator("command", mode="before")
    @classmethod
    def _command(cls, value: object) -> str:
        return ReplyValues().text(value, cls.COMMAND_CHARS)

    @field_validator("detail", mode="before")
    @classmethod
    def _detail(cls, value: object) -> str:
        return ReplyValues().text(value, cls.DETAIL_CHARS)


class NarrativeReply(BaseModel):
    """The incident narrator's digest."""

    model_config = ConfigDict(frozen=True)
    HEADLINE_CHARS: ClassVar[int] = 200
    SUMMARY_CHARS: ClassVar[int] = 2000
    MAX_TIMELINE: ClassVar[int] = 30
    MAX_ACTIONS: ClassVar[int] = 15

    headline: str = ""
    severity: str = IncidentSeverity.LOW.value
    summary: str = ""
    timeline: list[TimelineEvent] = []
    actions: list[NarrativeAction] = []

    @field_validator("headline", mode="before")
    @classmethod
    def _headline(cls, value: object) -> str:
        return ReplyValues().text(value, cls.HEADLINE_CHARS)

    @field_validator("severity", mode="before")
    @classmethod
    def _severity(cls, value: object) -> str:
        return ReplyValues().choice(value, IncidentSeverity.LOW)

    @field_validator("summary", mode="before")
    @classmethod
    def _summary(cls, value: object) -> str:
        return ReplyValues().text(value, cls.SUMMARY_CHARS)

    @field_validator("timeline", mode="before")
    @classmethod
    def _events(cls, value: object) -> list[dict[str, Any]]:
        return ReplyValues().labelled(value, "title")[: cls.MAX_TIMELINE]

    @field_validator("actions", mode="before")
    @classmethod
    def _actions(cls, value: object) -> list[dict[str, Any]]:
        return ReplyValues().labelled(value, "title")[: cls.MAX_ACTIONS]

    def digest(self) -> dict[str, Any] | None:
        """None when the reply says nothing usable (no headline, or neither
        a summary nor a timeline)."""
        if not self.headline or not (self.summary or self.timeline):
            return None
        return {
            "headline": self.headline,
            "severity": self.severity,
            "summary": self.summary,
            "timeline": [event.model_dump() for event in self.timeline],
            "actions": [action.model_dump() for action in self.actions],
        }
