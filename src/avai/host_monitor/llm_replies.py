"""Contracts for the structured replies the LLM stages get back.

A model may leave a field out, send it empty or send the wrong type; the
stage must still get a usable value, as it did with the old hand-written
reader. Every field therefore has a default and a ``mode="before"``
validator that turns a bad value into that default instead of failing.
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, field_validator

from .enums import ThreatCategory, Verdict
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
