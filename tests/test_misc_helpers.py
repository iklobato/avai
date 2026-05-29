"""Targeted tests for small helpers that are easy to break but rarely
get attention: ``_sha256_of_file`` (used by every binary-hashing
extractor), the dashboard's ``_engine`` URL construction, and the
chain stats counters.
"""

from __future__ import annotations

import hashlib

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase

from avai.dashboard import _engine, _ensure_db_exists, app
from avai.enrichers import EnrichmentChain, EvidenceCache, Indicator, IndicatorType
from avai.enrichers.indicators import _safe_loads, _sha256_of_file

# ---------------------------------------------------------------------------
# _sha256_of_file — file hashing helper used by every binary indicator
# ---------------------------------------------------------------------------


class TestSha256OfFile:
    def test_returns_correct_hex_digest(self, tmp_path):
        p = tmp_path / "x.bin"
        p.write_bytes(b"hello world")
        expected = hashlib.sha256(b"hello world").hexdigest()
        assert _sha256_of_file(str(p)) == expected

    def test_nonexistent_path_returns_none(self):
        assert _sha256_of_file("/no/such/file") is None

    def test_directory_returns_none(self, tmp_path):
        # tmp_path is a directory — not hashable as a file.
        assert _sha256_of_file(str(tmp_path)) is None

    def test_empty_file_hashes_to_empty_sha256(self, tmp_path):
        p = tmp_path / "empty.bin"
        p.touch()
        expected = hashlib.sha256(b"").hexdigest()
        assert _sha256_of_file(str(p)) == expected

    def test_large_file_above_cap_returns_none(self, tmp_path):
        # The helper caps at 16 MB to avoid stalling on huge binaries.
        # Verify the cap is enforced. Sparse-write a 17 MB file via
        # truncate so we don't actually allocate 17 MB.
        p = tmp_path / "big.bin"
        with open(p, "wb") as f:
            f.truncate(17 * 1024 * 1024)
        assert _sha256_of_file(str(p)) is None

    def test_at_cap_boundary_is_hashed(self, tmp_path):
        # Exactly 16 MB → still hashed.
        p = tmp_path / "edge.bin"
        with open(p, "wb") as f:
            f.truncate(16 * 1024 * 1024)
        assert _sha256_of_file(str(p)) is not None


# ---------------------------------------------------------------------------
# _safe_loads — JSON parser for collector-emitted strings
# ---------------------------------------------------------------------------


class TestSafeLoads:
    def test_valid_json_object(self):
        assert _safe_loads('{"a": 1}') == {"a": 1}

    def test_valid_json_array(self):
        assert _safe_loads("[1, 2, 3]") == [1, 2, 3]

    def test_malformed_returns_none(self):
        assert _safe_loads("{not valid}") is None

    def test_empty_string_returns_none(self):
        assert _safe_loads("") is None

    def test_non_string_returns_none(self):
        assert _safe_loads(None) is None
        assert _safe_loads(42) is None
        assert _safe_loads(["already a list"]) is None


# ---------------------------------------------------------------------------
# Dashboard _engine — read-only URL construction
# ---------------------------------------------------------------------------


class TestDashboardEngine:
    def test_url_is_read_only_but_not_immutable(self, tmp_path):
        db = tmp_path / "x.db"
        _ensure_db_exists(str(db))
        app.config["DB_PATH"] = str(db)
        with app.app_context():
            url = str(_engine().url)
        # mode=ro = read-only; uri=true enables the file: URI form.
        assert "mode=ro" in url
        assert "uri=true" in url
        # immutable=1 must NOT be present — it ignores the WAL, which
        # made the dashboard 500 on a live DB still writing to its -wal.
        assert "immutable" not in url

    def test_engine_can_open_existing_db(self, tmp_path):
        db = tmp_path / "exists.db"
        _ensure_db_exists(str(db))
        app.config["DB_PATH"] = str(db)
        with app.app_context():
            e = _engine()
            with e.connect() as conn:
                # Anything that proves the connection works.
                conn.exec_driver_sql("select 1")


# ---------------------------------------------------------------------------
# EnrichmentChain stats — used by the per-cycle log line
# ---------------------------------------------------------------------------


class _Base(DeclarativeBase):
    pass


@pytest.fixture
def cache():
    engine = create_engine("sqlite:///:memory:")
    from avai.enrichers.cache import register_schema

    register_schema(_Base)
    _Base.metadata.create_all(engine)
    return EvidenceCache(engine, _Base)


class _Fake:
    def __init__(self, name, hint, ret=None, exc=None):
        self.name = name
        self.supports_types = frozenset({IndicatorType.IPV4})
        self.requires_token = None
        self.ttl_hours = 24
        self._ret = ret
        self._exc = exc

    def supports(self, ind):
        return ind.type in self.supports_types

    def freshness_cutoff(self):
        from datetime import datetime, timedelta, timezone

        return datetime.now(timezone.utc) - timedelta(hours=self.ttl_hours)

    def _fetch(self, ind):
        if self._exc:
            raise self._exc
        return self._ret


class TestChainStats:
    def test_records_hit_and_cached_separately(self, cache):
        from avai.enrichers.base import Evidence, VerdictHint

        ind = Indicator(IndicatorType.IPV4, "1.2.3.4")
        ev = Evidence(
            source="x",
            indicator=ind,
            verdict_hint=VerdictHint.MALICIOUS,
            confidence=0.9,
            summary="s",
        )
        e = _Fake("x", VerdictHint.MALICIOUS, ret=ev)
        chain = EnrichmentChain([e], cache)
        chain.enrich(ind)  # miss → hit + miss tallied
        chain.enrich(ind)  # cache hit → cached tallied
        stats = chain.stats()["x"]
        assert stats["hit"] == 1
        assert stats["miss"] == 1
        assert stats["cached"] == 1

    def test_records_none_response(self, cache):
        ind = Indicator(IndicatorType.IPV4, "1.2.3.4")
        e = _Fake("x", None, ret=None)
        chain = EnrichmentChain([e], cache)
        chain.enrich(ind)
        assert chain.stats()["x"]["none"] == 1

    def test_records_error(self, cache):
        ind = Indicator(IndicatorType.IPV4, "1.2.3.4")
        e = _Fake("x", None, exc=RuntimeError("boom"))
        chain = EnrichmentChain([e], cache)
        chain.enrich(ind)
        assert chain.stats()["x"]["error"] == 1

    def test_reset_stats_clears(self, cache):
        ind = Indicator(IndicatorType.IPV4, "1.2.3.4")
        from avai.enrichers.base import Evidence, VerdictHint

        e = _Fake(
            "x",
            VerdictHint.MALICIOUS,
            ret=Evidence(
                source="x",
                indicator=ind,
                verdict_hint=VerdictHint.MALICIOUS,
                confidence=0.9,
                summary="s",
            ),
        )
        chain = EnrichmentChain([e], cache)
        chain.enrich(ind)
        chain.reset_stats()
        assert chain.stats() == {}


# ---------------------------------------------------------------------------
# Sink.unjudged_all — streaming variant (no run_id filter)
# ---------------------------------------------------------------------------


class TestSinkUnjudgedAll:
    def test_returns_distinct_hashes_across_runs(self, tmp_path):
        # The streaming variant of unjudged ignores run_id so streaming
        # rows that span runs are still classified once each.
        from avai.host_monitor import (
            AuthEventRow,
            Judgment,
            Sink,
            ThreatCategory,
            Verdict,
            content_hash,
            utcnow,
        )

        class _S:
            name = "auth_events"
            model = AuthEventRow
            judge_enabled = True
            judge_fields = ("event_type", "event_message")
            judge_hints = ""

        db = tmp_path / "u.db"
        engine = create_engine(
            f"sqlite:///{db}", connect_args={"check_same_thread": False}
        )
        sink = Sink(engine)
        sink.setup()
        ts = utcnow()

        # Write two rows: one judged, one unjudged.
        h_judged = content_hash(
            {"event_type": "login_ok", "event_message": "alice"}, _S.judge_fields
        )
        h_unjudged = content_hash(
            {"event_type": "login_fail", "event_message": "bob"}, _S.judge_fields
        )
        sink.write(
            AuthEventRow,
            [
                {
                    "event_timestamp": ts,
                    "subsystem": "auth",
                    "category": "auth",
                    "process": "sshd",
                    "pid": 1,
                    "event_type": "login_ok",
                    "event_message": "alice",
                    "raw_json": "{}",
                    "content_hash": h_judged,
                    "run_id": "r1",
                    "collected_at": ts,
                },
                {
                    "event_timestamp": ts,
                    "subsystem": "auth",
                    "category": "auth",
                    "process": "sshd",
                    "pid": 2,
                    "event_type": "login_fail",
                    "event_message": "bob",
                    "raw_json": "{}",
                    "content_hash": h_unjudged,
                    "run_id": "r1",
                    "collected_at": ts,
                },
            ],
        )
        sink.write_judgments(
            [
                Judgment(
                    content_hash=h_judged,
                    collector="auth_events",
                    verdict=Verdict.BENIGN,
                    category=ThreatCategory.NONE,
                    confidence=1.0,
                    reasoning="ok",
                    remediation="",
                    model="m",
                    created_at=ts,
                )
            ]
        )

        result = sink.unjudged_all(_S())
        assert len(result) == 1
        assert result[0]["event_message"] == "bob"

    def test_returns_empty_when_collector_has_no_judge_fields(self, tmp_path):
        from avai.host_monitor import AuthEventRow, Sink

        class _S:
            name = "auth_events"
            model = AuthEventRow
            judge_enabled = True
            judge_fields = ()
            judge_hints = ""

        db = tmp_path / "z.db"
        engine = create_engine(
            f"sqlite:///{db}", connect_args={"check_same_thread": False}
        )
        sink = Sink(engine)
        sink.setup()
        assert sink.unjudged_all(_S()) == []
