"""The LLM reply contracts turn a malformed field into its default instead of
failing, exactly as the old hand-written reader did."""

from __future__ import annotations

import pytest

from avai.host_monitor.enums import ThreatCategory, Verdict
from avai.host_monitor.llm_replies import JudgmentReply, VerifierReply


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
        }

    def test_missing_fields_get_the_safe_defaults(self) -> None:
        assert JudgmentReply.model_validate({}).fields() == {
            "verdict": Verdict.UNKNOWN,
            "category": ThreatCategory.NONE,
            "confidence": 0.0,
            "reasoning": "",
            "remediation": "",
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
