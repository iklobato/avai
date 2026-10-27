"""The worst verdict a grouped dashboard row shows."""

from __future__ import annotations

from avai.dashboard.queries.panel_reads import VerdictRank


class TestVerdictRankWorst:
    LOW = 0.2
    HIGH = 0.9

    def test_the_worst_verdict_wins_and_the_first_one_keeps_a_tie(self) -> None:
        judged = [
            ("benign", self.LOW, "fine"),
            ("malicious", self.HIGH, "first bad"),
            ("malicious", self.LOW, "second bad"),
        ]

        assert VerdictRank().worst(judged) == {
            "verdict": "malicious",
            "confidence": self.HIGH,
            "reasoning": "first bad",
        }

    def test_unknown_or_missing_verdicts_leave_the_row_unjudged(self) -> None:
        judged = [(None, self.HIGH, "x"), ("nonsense", self.LOW, None)]

        assert VerdictRank().worst(judged) == {
            "verdict": None,
            "confidence": None,
            "reasoning": "",
        }

    def test_a_missing_reasoning_reads_as_empty_text(self) -> None:
        assert VerdictRank().worst([("suspicious", self.LOW, None)])["reasoning"] == ""
