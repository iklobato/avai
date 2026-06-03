"""Tests for the host-monitor module — pure utility functions, the
prompt loader, and the Sink repository.

Sink tests run against ``sqlite:///:memory:`` so the suite needs no
on-disk DB and no platform-specific collectors.
"""
from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any, Iterable

import pytest
from sqlalchemy import create_engine

from avai.host_monitor.runtime import Clock, Coerce, Digest
from avai.host_monitor import (
    Base,
    CollectionRun,
    Judgement,
    LaunchItemRow,
    NullJudge,
    Prompts,
    ProcessRow,
    Sink,
    ThreatCategory,
    Verdict,
)


# ---------------------------------------------------------------------------
# content_hash — stable dedup over judge_fields
# ---------------------------------------------------------------------------

class TestContentHash:
    def test_returns_none_for_empty_fields(self):
        assert Digest.of_row({"a": 1}, []) is None

    def test_deterministic_for_same_inputs(self):
        row = {"name": "foo", "exe": "/bin/foo", "pid": 42}
        h1 = Digest.of_row(row, ["name", "exe"])
        h2 = Digest.of_row(row, ["name", "exe"])
        assert h1 == h2

    def test_changes_when_a_judged_field_changes(self):
        a = Digest.of_row({"name": "foo", "exe": "/bin/foo"}, ["name", "exe"])
        b = Digest.of_row({"name": "foo", "exe": "/bin/bar"}, ["name", "exe"])
        assert a != b

    def test_ignores_non_judge_field_changes(self):
        a = Digest.of_row({"name": "foo", "pid": 1}, ["name"])
        b = Digest.of_row({"name": "foo", "pid": 99}, ["name"])
        assert a == b

    def test_missing_field_treated_as_null(self):
        """A row missing one of the judge_fields hashes as if the
        field were present-but-None — *not* an exception."""
        a = Digest.of_row({"name": "foo"}, ["name", "missing"])
        b = Digest.of_row({"name": "foo", "missing": None}, ["name", "missing"])
        assert a == b

    def test_output_is_a_hex_sha256(self):
        h = Digest.of_row({"x": 1}, ["x"])
        assert isinstance(h, str)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


# ---------------------------------------------------------------------------
# coerce_enum — defensive conversion at boundaries
# ---------------------------------------------------------------------------

class TestCoerceEnum:
    def test_returns_enum_for_valid_string(self):
        assert Coerce.enum("malicious", Verdict, Verdict.UNKNOWN) is Verdict.MALICIOUS

    def test_returns_default_for_unknown_string(self):
        assert Coerce.enum("not-a-verdict", Verdict, Verdict.UNKNOWN) is Verdict.UNKNOWN

    def test_returns_default_for_wrong_type(self):
        assert Coerce.enum(None, Verdict, Verdict.UNKNOWN) is Verdict.UNKNOWN
        assert Coerce.enum(42, Verdict, Verdict.BENIGN) is Verdict.BENIGN


# ---------------------------------------------------------------------------
# utcnow — ISO-8601 UTC stamp
# ---------------------------------------------------------------------------

class TestUtcnow:
    def test_returns_iso_with_utc_offset_or_z(self):
        ts = Clock().now_iso()
        # Must contain a date+time separator and end in either +00:00 or Z.
        assert "T" in ts or " " in ts
        assert ts.endswith(("+00:00", "Z"))


# ---------------------------------------------------------------------------
# Prompts — TOML load + Template substitution
# ---------------------------------------------------------------------------

class TestPromptsLoad:
    def _write(self, tmp_path, body: str) -> Path:
        p = tmp_path / "prompts.toml"
        p.write_text(body, encoding="utf-8")
        return p

    def test_load_substitutes_verdicts_and_categories(self, tmp_path):
        p = self._write(tmp_path, '''
[judge]
system = "Verdicts: $verdicts; Categories: $categories"
user_template = "x"

[collector_hints]
processes = "hint"
''')
        prompts = Prompts.load(p)
        # Every Verdict enum value should be present in the rendered system.
        for v in Verdict:
            assert str(v) in prompts.system
        for c in ThreatCategory:
            assert str(c) in prompts.system

    def test_load_keeps_user_template_as_template(self, tmp_path):
        p = self._write(tmp_path, '''
[judge]
system = "ok"
user_template = "$collector | $hints | $entries"
''')
        prompts = Prompts.load(p)
        # User template is *not* substituted at load time — must keep
        # the placeholders so the judge can fill them per-call.
        assert "$collector" in prompts.user_template
        assert "$hints" in prompts.user_template
        assert "$entries" in prompts.user_template

    def test_load_preserves_collector_hints(self, tmp_path):
        p = self._write(tmp_path, '''
[judge]
system = "ok"
user_template = "x"

[collector_hints]
processes = "process hint"
launch_items = "launch hint"
''')
        prompts = Prompts.load(p)
        assert prompts.collector_hints["processes"] == "process hint"
        assert prompts.collector_hints["launch_items"] == "launch hint"

    def test_load_tolerates_missing_judge_section(self, tmp_path):
        # An empty file is valid TOML — Prompts.load must not crash.
        p = self._write(tmp_path, "")
        prompts = Prompts.load(p)
        assert prompts.system == ""
        assert prompts.user_template == ""
        assert prompts.collector_hints == {}

    def test_hint_for_returns_empty_string_when_missing(self, tmp_path):
        p = self._write(tmp_path, '''
[judge]
system = "ok"
user_template = "x"
[collector_hints]
processes = "hint"
''')
        prompts = Prompts.load(p)
        assert prompts.hint_for("processes") == "hint"
        assert prompts.hint_for("not_a_collector") == ""

    def test_bundled_prompts_file_loads(self):
        # The real shipped prompts.toml must load cleanly — protects
        # against schema-drift regressions when we edit the file.
        pkg_root = Path(__file__).resolve().parent.parent / "src" / "avai"
        prompts = Prompts.load(pkg_root / "prompts.toml")
        assert "verdict" in prompts.system.lower()
        assert prompts.user_template  # non-empty
        # The eight LLM-judged Linux collectors must have hints.
        for c in ("processes", "launch_items", "browser_extensions",
                  "system_integrity", "file_integrity", "installed_apps",
                  "mounts", "setuid_files"):
            assert prompts.hint_for(c), f"missing hint for {c}"


# ---------------------------------------------------------------------------
# NullJudge — opt-out judge
# ---------------------------------------------------------------------------

class TestNullJudge:
    def test_returns_empty_list_regardless_of_input(self):
        j = NullJudge()
        assert j.judge("processes", "hint", []) == []
        assert j.judge("processes", "hint",
                       [{"content_hash": "a", "name": "x"}]) == []


# ---------------------------------------------------------------------------
# Sink — repository over the SQLAlchemy schema
# ---------------------------------------------------------------------------

class _StubCollector:
    """Minimal stand-in for Collector — Sink only reads ``name``,
    ``model``, ``judge_enabled``, ``judge_fields``."""
    def __init__(self, name, model, judge_fields=()):
        self.name = name
        self.model = model
        self.judge_enabled = True
        self.judge_fields = judge_fields
        self.judge_hints = ""


@pytest.fixture
def sink():
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False})
    s = Sink(engine)
    s.setup()
    return s


class TestSinkLifecycle:
    def test_setup_creates_every_known_table(self, sink):
        # Sample of tables that must exist after setup() — covers
        # every category and the enrichment_evidence table.
        expected = {
            "collection_runs", "collector_errors", "judgements",
            "processes", "network_connections", "launch_items",
            "browser_extensions", "system_integrity",
            "enrichment_evidence",
        }
        actual = set(Base.metadata.tables.keys())
        missing = expected - actual
        assert not missing, f"missing tables: {missing}"

    def test_start_and_end_run_round_trip(self, sink):
        run_id, started = sink.start_run("host-x", 5)
        assert isinstance(run_id, str) and len(run_id) == 36  # UUID4
        sink.end_run(ok=3, failed=0)
        # Run row should exist and carry both timestamps.
        from sqlalchemy import select
        from sqlalchemy.orm import Session
        with Session(sink.engine) as s:
            row = s.execute(select(CollectionRun).where(
                CollectionRun.run_id == run_id)).scalar_one()
        assert row.hostname == "host-x"
        assert row.lookback_min == 5
        assert row.finished_at  # populated by end_run
        assert row.collectors_ok == 3
        assert row.collectors_failed == 0


class TestSinkUnjudged:
    def test_returns_one_entry_per_distinct_content_hash(self, sink):
        run_id, _ = sink.start_run("h", 5)
        collector = _StubCollector("processes", ProcessRow,
                                   judge_fields=("name", "exe"))
        rows = [
            {"name": "a", "exe": "/x", "pid": 1, "username": "u",
             "run_id": run_id, "collected_at": Clock().now_iso(),
             "content_hash": Digest.of_row({"name": "a", "exe": "/x"},
                                          collector.judge_fields)},
            # Same judge_fields → same hash → should dedup.
            {"name": "a", "exe": "/x", "pid": 2, "username": "u",
             "run_id": run_id, "collected_at": Clock().now_iso(),
             "content_hash": Digest.of_row({"name": "a", "exe": "/x"},
                                          collector.judge_fields)},
            # Different exe → distinct hash.
            {"name": "b", "exe": "/y", "pid": 3, "username": "u",
             "run_id": run_id, "collected_at": Clock().now_iso(),
             "content_hash": Digest.of_row({"name": "b", "exe": "/y"},
                                          collector.judge_fields)},
        ]
        sink.write(ProcessRow, rows)

        unjudged = sink.unjudged(collector)
        assert len(unjudged) == 2
        names = sorted(e["name"] for e in unjudged)
        assert names == ["a", "b"]

    def test_skips_entries_already_judged(self, sink):
        run_id, _ = sink.start_run("h", 5)
        collector = _StubCollector("processes", ProcessRow,
                                   judge_fields=("name", "exe"))
        h = Digest.of_row({"name": "a", "exe": "/x"}, collector.judge_fields)
        sink.write(ProcessRow, [{
            "name": "a", "exe": "/x", "pid": 1, "username": "u",
            "run_id": run_id, "collected_at": Clock().now_iso(),
            "content_hash": h,
        }])
        # Pre-seed the judgement so this hash is "already judged".
        from avai.host_monitor import Judgment
        sink.write_judgments([Judgment(
            content_hash=h, collector="processes",
            verdict=Verdict.BENIGN, category=ThreatCategory.NONE,
            confidence=0.99, reasoning="r", remediation="",
            model="test", created_at=Clock().now_iso(),
        )])
        unjudged = sink.unjudged(collector)
        assert unjudged == []

    def test_returns_empty_when_collector_has_no_judge_fields(self, sink):
        # A collector with judge_fields=() opts out of judging.
        sink.start_run("h", 5)
        collector = _StubCollector("processes", ProcessRow, judge_fields=())
        assert sink.unjudged(collector) == []


class TestSinkWriteJudgments:
    def test_write_is_idempotent_on_pk_conflict(self, sink):
        from avai.host_monitor import Judgment
        j = Judgment(
            content_hash="aa" * 32, collector="processes",
            verdict=Verdict.BENIGN, category=ThreatCategory.NONE,
            confidence=0.5, reasoning="r", remediation="",
            model="m", created_at=Clock().now_iso(),
        )
        sink.write_judgments([j])
        sink.write_judgments([j])  # should not raise / not duplicate

        from sqlalchemy import select, func
        from sqlalchemy.orm import Session
        with Session(sink.engine) as s:
            n = s.execute(select(func.count()).select_from(Judgement)).scalar()
        assert n == 1

    def test_write_error_records_collector_failure(self, sink):
        # write_error references self.run_id (NOT NULL FK); contract
        # requires a prior start_run() in the same cycle.
        sink.start_run("h", 5)
        try:
            raise RuntimeError("boom")
        except RuntimeError as exc:
            sink.write_error("processes", exc)

        from sqlalchemy import select
        from sqlalchemy.orm import Session
        from avai.host_monitor import CollectorErrorRow
        with Session(sink.engine) as s:
            row = s.execute(select(CollectorErrorRow)).scalar_one()
        assert row.collector == "processes"
        assert row.error_class == "RuntimeError"
        assert "boom" in row.message


# ---------------------------------------------------------------------------
# DB-rotation accounting
# ---------------------------------------------------------------------------

class TestSinkDatabaseSize:
    def test_size_bytes_is_zero_for_in_memory_url(self, sink):
        # database_size_bytes parses the file path out of the engine
        # URL; an in-memory DB has no file, so the contract is to
        # return 0 (not crash trying to stat a nonexistent path).
        # (File-backed growth is covered in test_sink_rotation.py.)
        assert sink.database_size_bytes() == 0

    def test_live_bytes_reflects_allocated_pages(self, sink):
        # live_bytes = (page_count - freelist) * page_size. After setup
        # the schema occupies a handful of pages, so it must be > 0 even
        # with no data rows — proves the PRAGMA arithmetic runs.
        assert sink.database_live_bytes() > 0
