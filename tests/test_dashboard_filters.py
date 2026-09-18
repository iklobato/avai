"""RowFilter, LogFilter and FindingFilter: the filters dashboard panels take."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from avai.dashboard.queries import FindingFilter, LogFilter, RowFilter, findings
from avai.host_monitor import Judgment, Sink, ThreatCategory, Verdict

_ROWS = [
    {"verdict": "malicious", "process": "curl", "port": 4444},
    {"verdict": "benign", "process": "sshd", "port": 22},
    {"verdict": None, "process": None, "port": 8022},
]


class TestRowFilter:
    def test_no_filter_keeps_every_row(self):
        assert RowFilter().keep(_ROWS, ("process",)) == _ROWS

    def test_verdict_keeps_only_that_verdict(self):
        kept = RowFilter(verdict="benign").keep(_ROWS, ("process",))
        assert [r["process"] for r in kept] == ["sshd"]

    def test_search_is_case_insensitive_over_the_given_fields(self):
        kept = RowFilter(q="SSH").keep(_ROWS, ("process",))
        assert [r["process"] for r in kept] == ["sshd"]

    def test_search_ignores_the_case_of_the_row_value(self):
        rows = [{"verdict": None, "process": "Google Chrome"}]
        assert RowFilter(q="chrome").keep(rows, ("process",)) == rows

    def test_search_matches_numbers_and_skips_missing_values(self):
        kept = RowFilter(q="22").keep(_ROWS, ("process", "port"))
        assert [r["port"] for r in kept] == [22, 8022]

    def test_search_ignores_fields_not_listed(self):
        assert RowFilter(q="curl").keep(_ROWS, ("port",)) == []

    def test_fields_echo_the_values(self):
        assert RowFilter("suspicious", "x").fields() == {
            "verdict": "suspicious",
            "q": "x",
        }


def _line(source, level, message, unit=None):
    return SimpleNamespace(source=source, level=level, message=message, unit=unit)


_LINES = [
    _line("journald", "err", "disk failure", unit="kernel"),
    _line("journald", "info", "Accepted password", unit="sshd"),
    _line("/var/log/dpkg.log", "info", "status installed openssl", unit=None),
]


class TestLogFilter:
    def test_filters_combine(self):
        kept = LogFilter(source="journald", level="info").keep(_LINES)
        assert [r.unit for r in kept] == ["sshd"]

    def test_search_covers_message_and_unit(self):
        assert len(LogFilter(q="SSHD").keep(_LINES)) == 1
        assert len(LogFilter(q="openssl").keep(_LINES)) == 1

    def test_fields_echo_the_values(self):
        assert LogFilter("a", "b", "c").fields() == {
            "source": "a",
            "level": "b",
            "q": "c",
        }


_LONG_AGO = "2000-01-01T00:00:00+00:00"


@pytest.fixture
def judged(tmp_path):
    """Two suspicious findings: one seen in the latest run, one last seen
    long before it (resolved)."""
    engine = create_engine(f"sqlite:///{tmp_path / 'f.db'}")
    sink = Sink(engine)
    sink.setup()
    _, started = sink.start_run("h", 5)
    sink.end_run(ok=1, failed=0)
    for content_hash, reasoning, seen_at in (
        ("a" * 64, "beacon to a raw IP", started),
        ("b" * 64, "unsigned launch agent", _LONG_AGO),
    ):
        sink.write_judgments(
            [
                Judgment(
                    content_hash=content_hash,
                    collector="launch_items",
                    verdict=Verdict.SUSPICIOUS,
                    category=ThreatCategory.PERSISTENCE,
                    confidence=0.7,
                    reasoning=reasoning,
                    remediation="x",
                    model="m",
                    created_at=started,
                )
            ]
        )
        sink.touch_judgments("launch_items", [content_hash], seen_at)
    return engine


def _reasons(engine, filters: FindingFilter) -> list[str]:
    with Session(engine) as s:
        return [f["reasoning"] for f in findings(s, filters=filters)["items"]]


class TestFindingFilter:
    def test_active_is_the_default(self, judged):
        assert _reasons(judged, FindingFilter()) == ["beacon to a raw IP"]

    def test_resolved_shows_findings_not_seen_in_the_latest_run(self, judged):
        assert _reasons(judged, FindingFilter(status="resolved")) == [
            "unsigned launch agent"
        ]

    def test_search_is_case_insensitive_over_the_reasoning(self, judged):
        assert _reasons(judged, FindingFilter(search="UNSIGNED", status="all")) == [
            "unsigned launch agent"
        ]

    def test_benign_is_hidden_unless_picked(self, judged):
        assert _reasons(judged, FindingFilter(verdict="benign", status="all")) == []
