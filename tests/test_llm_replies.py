"""The LLM reply contracts turn a malformed field into its default instead of
failing, exactly as the old hand-written reader did."""

from __future__ import annotations

import pytest

from avai.host_monitor.enums import ThreatCategory, Verdict
from avai.host_monitor.llm_replies import (
    CoverageReply,
    JudgmentReply,
    NarrativeReply,
    VerifierReply,
)


class TestJudgmentReply:
    CONFIDENCE = 0.8
    NOT_A_CATEGORY = 3
    OVERFLOW = 1000

    def test_a_well_formed_item_keeps_its_values(self) -> None:
        reply = JudgmentReply.model_validate(
            {
                "verdict": " Malicious ",
                "category": "PERSISTENCE",
                "confidence": str(self.CONFIDENCE),
                "reasoning": "  plist runs curl|bash  ",
                "remediation": "unload it",
            }
        )

        assert reply.fields() == {
            "verdict": Verdict.MALICIOUS,
            "category": ThreatCategory.PERSISTENCE,
            "confidence": self.CONFIDENCE,
            "reasoning": "  plist runs curl|bash  ",
            "remediation": "unload it",
            # Optional field the model left out: a verdict still comes back.
            "remediation_plain": "",
        }

    def test_the_plain_fix_is_kept_in_one_line(self) -> None:
        reply = JudgmentReply.model_validate(
            {
                "verdict": "malicious",
                "remediation_plain": "  Remove the item\nthat starts it.  ",
            }
        )
        assert reply.remediation_plain == "Remove the item that starts it."

    def test_missing_fields_get_the_safe_defaults(self) -> None:
        assert JudgmentReply.model_validate({}).fields() == {
            "verdict": Verdict.UNKNOWN,
            "category": ThreatCategory.NONE,
            "confidence": 0.0,
            "reasoning": "",
            "remediation": "",
            "remediation_plain": "",
        }

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [(7, 1.0), (-2, 0.0), ("lots", 0.0), (None, 0.0), ([1], 0.0)],
    )
    def test_confidence_is_clamped_or_zero(self, raw: object, expected: float) -> None:
        assert JudgmentReply.model_validate({"confidence": raw}).confidence == expected

    def test_unknown_verdict_and_category_fall_back(self) -> None:
        reply = JudgmentReply.model_validate(
            {"verdict": "evil", "category": self.NOT_A_CATEGORY}
        )

        assert (reply.verdict, reply.category) == (Verdict.UNKNOWN, ThreatCategory.NONE)

    def test_long_text_is_cut_to_the_column_size(self) -> None:
        reply = JudgmentReply.model_validate(
            {
                "reasoning": "r" * (JudgmentReply.REASONING_CHARS + self.OVERFLOW),
                "remediation": "m" * (JudgmentReply.REMEDIATION_CHARS + self.OVERFLOW),
            }
        )

        assert len(reply.reasoning) == JudgmentReply.REASONING_CHARS
        assert len(reply.remediation) == JudgmentReply.REMEDIATION_CHARS


class TestVerifierReply:
    def test_refuted_reply_is_stripped(self) -> None:
        reply = VerifierReply.model_validate(
            {"refuted": 1, "reasoning": "  benign updater  "}
        )

        assert reply.fields() == {"refuted": True, "reasoning": "benign updater"}

    def test_empty_reply_is_not_refuted(self) -> None:
        assert VerifierReply.model_validate({"refuted": ""}).fields() == {
            "refuted": False,
            "reasoning": "",
        }


class TestNarrativeReply:
    def test_unlabelled_and_non_object_entries_are_dropped(self) -> None:
        timeline = [{"title": " "}, "junk", {"title": "Ran", "category": "EXEC"}]
        reply = NarrativeReply.model_validate(
            {
                "headline": "Beacon",
                "summary": "x",
                "timeline": timeline,
                "actions": "no",
            }
        )

        assert [event.model_dump() for event in reply.timeline] == [
            {"time": "", "title": "Ran", "category": "exec", "detail": ""}
        ]
        assert reply.actions == []

    def test_entries_are_capped(self) -> None:
        count = NarrativeReply.MAX_TIMELINE + 1
        events = [{"title": f"e{index}"} for index in range(count)]

        reply = NarrativeReply.model_validate({"headline": "h", "timeline": events})

        assert len(reply.timeline) == NarrativeReply.MAX_TIMELINE

    def test_unknown_severity_and_priority_fall_back(self) -> None:
        reply = NarrativeReply.model_validate(
            {
                "headline": "h",
                "summary": "s",
                "severity": "apocalyptic",
                "actions": [{"title": "Kill it", "priority": "whenever"}],
            }
        )

        digest = reply.digest()
        assert digest is not None
        assert digest["severity"] == "low"
        assert digest["actions"][0]["priority"] == "medium"

    def test_no_headline_means_no_digest(self) -> None:
        assert NarrativeReply.model_validate({"summary": "s"}).digest() is None


class TestCoverageReply:
    def test_gaps_keep_only_labelled_areas(self) -> None:
        reply = CoverageReply.model_validate(
            {
                "headline": "h",
                "posture": "THIN",
                "gaps": [{"area": "macOS", "detail": "d"}, {"detail": "no area"}],
            }
        )

        assert reply.assessment() == {
            "posture": "thin",
            "headline": "h",
            "summary": "",
            "gaps": [{"area": "macOS", "detail": "d"}],
            "recommendations": [],
        }

    def test_headline_without_summary_or_gaps_is_dropped(self) -> None:
        assert CoverageReply.model_validate({"headline": "h"}).assessment() is None
