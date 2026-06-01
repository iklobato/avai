"""Tests for the read-only Flask dashboard.

The dashboard has two surfaces we lock down:

  1. ``_ensure_db_exists`` — the bug that earlier 500'd every panel on
     a fresh mount. This file pins the regression.
  2. The HTTP endpoints — Flask test client hits each route against
     an empty schema and asserts a 200, empty-shape response.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from avai.dashboard import _engine, _ensure_db_exists, app, latest_run, system_integrity
from avai.host_monitor import Sink, SystemIntegrityRow

# ---------------------------------------------------------------------------
# _ensure_db_exists — regression for the read-only 500 bug
# ---------------------------------------------------------------------------


class TestEnsureDbExists:
    def test_creates_file_when_missing(self, tmp_path):
        db = tmp_path / "new.db"
        assert not db.exists()
        _ensure_db_exists(str(db))
        assert db.exists()
        assert db.stat().st_size > 0  # schema bytes written

    def test_creates_parent_directory(self, tmp_path):
        db = tmp_path / "nested" / "deeper" / "avai.db"
        _ensure_db_exists(str(db))
        assert db.exists()

    def test_adds_missing_tables_to_existing_db_preserving_data(self, tmp_path):
        """Regression: a DB written by an OLDER monitor lacks a newly-added
        table (e.g. control_state). _ensure_db_exists must add it on startup
        WITHOUT touching existing data, so the read-only dashboard doesn't
        500 on the new panel. This is the general 'every new table' fix."""
        import sqlite3

        from avai.host_monitor import CollectionRun, Sink

        db = tmp_path / "old.db"
        Sink(create_engine(f"sqlite:///{db}")).setup()  # full current schema
        with Session(_engine_rw(str(db))) as s:  # seed real data
            s.add(
                CollectionRun(
                    run_id="r1",
                    started_at="2026-01-01T00:00:00Z",
                    hostname="h",
                    lookback_min=5,
                )
            )
            s.commit()
        # Emulate an old DB: drop the table a later version introduced.
        con = sqlite3.connect(str(db))
        con.execute("DROP TABLE control_state")
        con.commit()
        con.close()

        _ensure_db_exists(str(db))  # must re-add it, idempotently

        con = sqlite3.connect(str(db))
        tables = {
            r[0]
            for r in con.execute("select name from sqlite_master where type='table'")
        }
        runs = con.execute("select count(*) from collection_runs").fetchone()[0]
        con.close()
        assert "control_state" in tables  # missing table added
        assert runs == 1  # existing data preserved, not wiped

    def test_schema_is_queryable_after_create(self, tmp_path):
        """The bug it regresses against: dashboard opens the file with
        ``mode=ro&immutable=1`` — that mode requires the schema to
        already exist. Verify every collector table is present."""
        db = tmp_path / "fresh.db"
        _ensure_db_exists(str(db))

        # Open the file the same way the dashboard does.
        engine = create_engine(
            f"sqlite:///file:{db}?mode=ro&immutable=1&uri=true",
        )
        with engine.connect() as conn:
            from sqlalchemy import text

            names = [
                r[0]
                for r in conn.execute(
                    text("select name from sqlite_master where type='table'")
                )
            ]
        # The fix's contract — every model table must exist on the
        # fresh DB, so the dashboard's queries don't 500.
        for required in (
            "collection_runs",
            "processes",
            "launch_items",
            "judgements",
            "enrichment_evidence",
        ):
            assert required in names


# ---------------------------------------------------------------------------
# Flask test client — every endpoint must answer 200 on an empty DB
# ---------------------------------------------------------------------------


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Bind the Flask app to a fresh empty DB and return its test
    client. Avoids the real app.run() loop entirely."""
    db = tmp_path / "test.db"
    _ensure_db_exists(str(db))
    app.config.update(TESTING=True, DB_PATH=str(db))
    with app.test_client() as c:
        yield c


class TestDashboardEndpoints:
    def test_root_returns_html_page(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert b"<html" in r.data or b"<!doctype html" in r.data.lower()

    def test_findings_huge_page_does_not_500(self, client):
        # Regression: an out-of-range ?page= used to build an OFFSET past
        # SQLite's 64-bit INTEGER range, raising OverflowError -> HTTP 500.
        # findings() now clamps page to the last page (like _paginate).
        for page in ("10000000000000000000", "99999999", "-5"):
            r = client.get(f"/fragments/findings?page={page}&per_page=200")
            assert r.status_code == 200, f"page={page} returned {r.status_code}"

    def test_notifications_endpoint_returns_empty_items(self, client):
        # This is what the Docker HEALTHCHECK hits.
        r = client.get("/api/notifications/new?since=2099-01-01")
        assert r.status_code == 200
        body = r.get_json()
        assert body == {
            "items": [],
            "now": body["now"],  # presence — value is a timestamp
            "since": "2099-01-01",
        }

    def test_chart_verdicts_shape_on_empty_db(self, client):
        r = client.get("/api/chart/verdicts")
        assert r.status_code == 200
        body = r.get_json()
        # Contract: {"labels": [...], "datasets": {verdict: [counts]}}.
        # Even with no data the keys must exist and datasets must carry
        # an entry for every verdict — the Chart.js front-end indexes
        # into these by name, so a missing key silently breaks the donut.
        assert body["labels"] == []
        assert set(body["datasets"].keys()) == {
            "benign",
            "suspicious",
            "malicious",
            "unknown",
        }
        assert all(v == [] for v in body["datasets"].values())

    @pytest.mark.parametrize(
        "path",
        [
            "/fragments/header-meta",
            "/fragments/overview",
            "/fragments/incident",
            "/fragments/risk",
            "/fragments/sysint",
            "/fragments/errors",
            "/fragments/row-counts",
            "/fragments/runs",
            # merged panels
            "/fragments/posture",
            "/fragments/verdicts",
            "/fragments/collection",
            "/fragments/network",
            "/fragments/vulnerabilities",
        ],
    )
    def test_each_htmx_fragment_returns_200_on_empty_db(self, client, path):
        r = client.get(path)
        assert r.status_code == 200, f"{path} → {r.status_code}"

    def test_posture_merges_risk_and_integrity(self, client):
        body = client.get("/fragments/posture").data.decode()
        # both sub-panels present in one panel
        assert "posture score" in body
        assert "system integrity" in body

    def test_verdicts_merges_donut_and_trend(self, client):
        body = client.get("/fragments/verdicts").data.decode()
        assert 'id="verdict-donut"' in body  # all-time totals donut
        assert 'id="verdict-chart"' in body  # 12h trend canvas

    def test_collection_merges_runs_errors_rowcounts(self, client):
        body = client.get("/fragments/collection").data.decode()
        assert "rows per collector" in body
        assert "recent runs" in body
        assert "collector errors" in body

    def test_network_tabs_present(self, client):
        body = client.get("/fragments/network").data.decode()
        assert "listening ports" in body
        assert "outbound flows" in body
        assert "dns queries" in body
        assert "js-net-tab" in body

    def test_vulnerabilities_panel_renders_cves_and_kev(self, client):
        import json as _json

        from avai.dashboard import Base
        from avai.enrichers.cache import register_schema

        model = register_schema(Base)
        with Session(_engine_rw(app.config["DB_PATH"])) as s:
            s.add(
                model(
                    source="osv",
                    indicator_type="package",
                    indicator_value="openssl@3.0.2",
                    verdict_hint="suspicious",
                    confidence=0.75,
                    summary="OSV: 1 advisory hit(s): CVE-2024-0001",
                    details_json=_json.dumps({"vuln_ids": ["CVE-2024-0001"]}),
                    fetched_at="2026-05-30T12:00:00Z",
                )
            )
            # forward-chaining enriched that CVE: KEV (cisa_kev) + CVSS (nvd)
            s.add(
                model(
                    source="cisa_kev",
                    indicator_type="cve",
                    indicator_value="CVE-2024-0001",
                    verdict_hint="malicious",
                    confidence=0.98,
                    summary="actively exploited",
                    details_json="{}",
                    fetched_at="2026-05-30T12:00:00Z",
                )
            )
            s.add(
                model(
                    source="nvd",
                    indicator_type="cve",
                    indicator_value="CVE-2024-0001",
                    verdict_hint="malicious",
                    confidence=0.7,
                    summary="NVD: CVSS=9.8 CRITICAL",
                    details_json=_json.dumps(
                        {"cvss31": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                    ),
                    fetched_at="2026-05-30T12:00:00Z",
                )
            )
            s.add(
                model(
                    source="endoflife",
                    indicator_type="os_version",
                    indicator_value="macos@12",
                    verdict_hint="suspicious",
                    confidence=0.6,
                    summary="EOL since 2024",
                    details_json="{}",
                    fetched_at="2026-05-30T12:00:00Z",
                )
            )
            # a benign endoflife row must NOT appear (still-supported OS)
            s.add(
                model(
                    source="endoflife",
                    indicator_type="os_version",
                    indicator_value="macos@15",
                    verdict_hint="benign",
                    confidence=0.1,
                    summary="supported",
                    details_json="{}",
                    fetched_at="2026-05-30T12:00:00Z",
                )
            )
            s.commit()
        body = client.get("/fragments/vulnerabilities").data.decode()
        assert "openssl@3.0.2" in body and "CVE-2024-0001" in body
        assert "KEV" in body  # forward-chained actively-exploited flag
        assert "9.8" in body  # forward-chained CVSS from NVD
        assert "macos@12" in body  # EOL surfaced
        assert "macos@15" not in body  # benign filtered out
        # the KEV/critical package must rank before the EOL OS
        assert body.index("openssl@3.0.2") < body.index("macos@12")

    def test_incident_fragment_empty_shows_placeholder(self, client):
        r = client.get("/fragments/incident")
        assert r.status_code == 200
        assert b"no incident digest yet" in r.data

    def test_incident_fragment_renders_latest_narrative(self, client):
        from avai.host_monitor import IncidentNarrativeRow

        with Session(_engine_rw(app.config["DB_PATH"])) as s:
            s.add(
                IncidentNarrativeRow(
                    created_at="2026-05-30T12:00:00Z",
                    run_id="r1",
                    model="m",
                    severity="critical",
                    headline="C2 beacon from /tmp binary",
                    summary="A novel binary beaconed to a flagged IP.",
                    timeline_json=(
                        '[{"time":"2026-05-30T18:54","title":"binary launched",'
                        '"category":"command_and_control","detail":"hit 9.9.9.9"}]'
                    ),
                    actions_json=(
                        '[{"priority":"immediate","title":"kill process",'
                        '"command":"kill 123","detail":"stop it"}]'
                    ),
                    finding_count=2,
                    finding_hashes='["a","b"]',
                )
            )
            s.commit()
        r = client.get("/fragments/incident")
        assert r.status_code == 200
        body = r.data.decode()
        assert "C2 beacon from /tmp binary" in body
        assert "critical" in body
        assert "2 active findings" in body
        # structured timeline rendered as a vertical timeline, not raw JSON
        assert 'class="timeline"' in body
        assert "binary launched" in body
        assert "command and control" in body  # underscore → space in chip
        # structured actions rendered as cards
        assert "kill process" in body
        assert "kill 123" in body
        assert '"title":' not in body  # raw JSON must not leak through

    def test_incident_legacy_narrative_still_renders(self, client):
        # A digest written before the structured format (only the old
        # `narrative` field) must still render via the markdown fallback,
        # with any injected <script> stripped.
        from avai.host_monitor import IncidentNarrativeRow

        with Session(_engine_rw(app.config["DB_PATH"])) as s:
            s.add(
                IncidentNarrativeRow(
                    created_at="2026-05-30T13:00:00Z",
                    run_id="r2",
                    model="m",
                    severity="high",
                    headline="legacy",
                    narrative="ok <script>alert(1)</script> **done**",
                    finding_count=1,
                    finding_hashes="[]",
                )
            )
            s.commit()
        r = client.get("/fragments/incident")
        assert r.status_code == 200
        assert b"<script" not in r.data  # sanitised
        assert b"<strong>done</strong>" in r.data  # markdown fallback rendered

    def test_findings_surface_novel_badge_and_context(self, client):
        # A finding carrying the baseline novelty + correlated process story
        # must render the 'novel' badge and the behavioural-context block.
        from avai.host_monitor import CollectionRun, Judgement

        with Session(_engine_rw(app.config["DB_PATH"])) as s:
            s.add(
                CollectionRun(
                    run_id="run1",
                    started_at="2026-05-30T12:00:00Z",
                    finished_at="2026-05-30T12:01:00Z",
                    hostname="h",
                    lookback_min=5,
                )
            )
            s.add(
                Judgement(
                    content_hash="hh",
                    collector="processes",
                    verdict="malicious",
                    category="persistence",
                    confidence=0.9,
                    reasoning="bad",
                    remediation="kill",
                    model="m",
                    created_at="2026-05-30T12:00:30Z",
                    last_seen_at="2026-05-30T12:00:00Z",  # == run start → active
                    novel=1,
                    context_json=(
                        '{"baseline":{"novel":true,"first_seen":"2026-05-30T11:59",'
                        '"times_seen":2,"host_runs":20,"baseline_established":true},'
                        '"related":{"listening_ports":["0.0.0.0:4444"],'
                        '"outbound_flows":[{"dst":"9.9.9.9:443","service":"https","packets":120}]}}'
                    ),
                )
            )
            s.commit()
        r = client.get("/fragments/findings")
        assert r.status_code == 200
        body = r.data.decode()
        assert "novel" in body  # badge
        assert "behavioural context" in body  # detail section
        assert "0.0.0.0:4444" in body  # correlated listening port
        assert "9.9.9.9:443" in body  # correlated outbound flow

    def test_risk_fragment_renders_score_and_drivers(self, client):
        from avai.host_monitor import RiskScoreRow

        with Session(_engine_rw(app.config["DB_PATH"])) as s:
            s.add(
                RiskScoreRow(
                    created_at="2026-05-30T12:00:00Z",
                    run_id="r1",
                    score=72,
                    grade="C",
                    prev_score=85,
                    drivers_json='[{"label":"Firewall off","points":15}]',
                    explanation="Score down 13. New: Firewall off.",
                )
            )
            s.commit()
        r = client.get("/fragments/risk")
        assert r.status_code == 200
        body = r.data.decode()
        assert ">C<" in body or "C" in body  # grade
        assert "72" in body  # score
        assert "Firewall off" in body  # driver
        assert "−15" in body or "-15" in body  # driver points
        assert "<polyline" in body  # sparkline (1 point series)
        assert "Score down 13" in body  # explanation

    def test_risk_fragment_empty_shows_placeholder(self, client):
        r = client.get("/fragments/risk")
        assert r.status_code == 200
        assert b"no posture score yet" in r.data

    def test_overview_shows_total_llm_cost(self, client):
        from avai.host_monitor import CollectionRun, Judgement

        with Session(_engine_rw(app.config["DB_PATH"])) as s:
            s.add(
                CollectionRun(
                    run_id="run1",
                    started_at="2026-05-30T12:00:00Z",
                    finished_at="2026-05-30T12:01:00Z",
                    hostname="h",
                    lookback_min=5,
                )
            )
            for h, c in (("a", 0.001), ("b", 0.0005)):
                s.add(
                    Judgement(
                        content_hash=h,
                        collector="processes",
                        verdict="benign",
                        category="none",
                        confidence=0.9,
                        reasoning="",
                        remediation="",
                        model="m",
                        created_at="2026-05-30T12:00:30Z",
                        last_seen_at="2026-05-30T12:00:00Z",
                        cost_usd=c,
                    )
                )
            s.commit()
        r = client.get("/fragments/overview")
        assert r.status_code == 200
        body = r.data.decode()
        assert "est. LLM cost" in body
        assert "$0.0015" in body  # 0.001 + 0.0005, summed since the run

    def test_row_counts_shows_total_and_delta(self, client):
        from avai.host_monitor import CollectionRun, ProcessRow

        with Session(_engine_rw(app.config["DB_PATH"])) as s:
            for rid, ts in (
                ("r0", "2026-05-30T11:00:00Z"),
                ("r1", "2026-05-30T12:00:00Z"),
            ):
                s.add(
                    CollectionRun(
                        run_id=rid,
                        started_at=ts,
                        finished_at=ts,
                        hostname="h",
                        lookback_min=5,
                    )
                )
            for i in range(3):  # previous run: 3 processes
                s.add(
                    ProcessRow(
                        pid=i,
                        name=f"a{i}",
                        run_id="r0",
                        collected_at="2026-05-30T11:00:00Z",
                    )
                )
            for i in range(5):  # latest run: 5 processes → delta +2
                s.add(
                    ProcessRow(
                        pid=i,
                        name=f"b{i}",
                        run_id="r1",
                        collected_at="2026-05-30T12:00:00Z",
                    )
                )
            s.commit()
        r = client.get("/fragments/row-counts")
        assert r.status_code == 200
        body = r.data.decode()
        assert "total" in body  # summary total
        assert "▲ +2" in body  # processes grew 3 → 5
        assert "empty" in body  # other collectors have 0 rows

    def test_finding_detail_shows_per_judgement_cost(self, client):
        from avai.host_monitor import CollectionRun, Judgement

        with Session(_engine_rw(app.config["DB_PATH"])) as s:
            s.add(
                CollectionRun(
                    run_id="run1",
                    started_at="2026-05-30T12:00:00Z",
                    finished_at="2026-05-30T12:01:00Z",
                    hostname="h",
                    lookback_min=5,
                )
            )
            s.add(
                Judgement(
                    content_hash="hh",
                    collector="processes",
                    verdict="malicious",
                    category="persistence",
                    confidence=0.9,
                    reasoning="bad",
                    remediation="kill",
                    model="m",
                    created_at="2026-05-30T12:00:30Z",
                    last_seen_at="2026-05-30T12:00:00Z",
                    cost_usd=0.000123,
                )
            )
            s.commit()
        r = client.get("/fragments/findings")
        assert r.status_code == 200
        body = r.data.decode()
        assert "est. LLM cost" in body
        assert "$0.000123" in body


class TestRowCountsDelta:
    def test_delta_and_is_new(self, tmp_path):
        from avai.dashboard import row_counts
        from avai.host_monitor import ListeningPortRow, ProcessRow, Sink

        eng = create_engine(
            f"sqlite:///{tmp_path / 'rc.db'}",
            connect_args={"check_same_thread": False},
        )
        sink = Sink(eng)
        sink.setup()
        prev, cur = "2026-05-30T11:00:00Z", "2026-05-30T12:00:00Z"
        sink.write(
            ProcessRow,
            [
                {"pid": i, "name": f"p{i}", "run_id": "r0", "collected_at": prev}
                for i in range(3)
            ],
        )
        sink.write(
            ProcessRow,
            [
                {"pid": i, "name": f"p{i}", "run_id": "r1", "collected_at": cur}
                for i in range(5)
            ],
        )
        sink.write(
            ListeningPortRow,
            [{"pid": 1, "laddr_port": 22, "run_id": "r1", "collected_at": cur}],
        )
        with Session(eng) as s:
            # snapshot collectors are counted by run_id now
            counts = {c["name"]: c for c in row_counts(s, "r1", cur, "r0", prev)}
        assert counts["processes"]["rows"] == 5
        assert counts["processes"]["delta"] == 2  # 5 − 3
        assert counts["processes"]["is_new"] is False
        assert counts["listening_ports"]["rows"] == 1
        assert counts["listening_ports"]["is_new"] is True  # 0 → 1


class TestDatetimeFmt:
    def test_formats_iso_to_human_utc(self):
        from avai.dashboard import _datetime_fmt

        assert (
            _datetime_fmt("2026-05-30T18:57:20+00:00") == "May 30, 2026 · 18:57:20 UTC"
        )

    def test_naive_timestamp_assumed_utc(self):
        from avai.dashboard import _datetime_fmt

        assert _datetime_fmt("2026-05-30T18:57:20") == "May 30, 2026 · 18:57:20 UTC"

    def test_non_utc_offset_converted_to_utc(self):
        from avai.dashboard import _datetime_fmt

        # 20:57 +02:00 == 18:57 UTC
        assert (
            _datetime_fmt("2026-05-30T20:57:20+02:00") == "May 30, 2026 · 18:57:20 UTC"
        )

    def test_empty_and_garbage_pass_through(self):
        from avai.dashboard import _datetime_fmt

        assert _datetime_fmt("") == ""
        assert _datetime_fmt("not-a-date") == "not-a-date"


def _engine_rw(db_path):
    # The dashboard opens read-only; tests need a writable engine to seed.
    return create_engine(
        f"sqlite:///{db_path}", connect_args={"check_same_thread": False}
    )

    def test_findings_fragment_supports_pagination_param(self, client):
        # Empty DB but the param-parsing must not crash.
        r = client.get("/fragments/findings?page=1")
        assert r.status_code == 200

    def test_unknown_endpoint_is_404_not_500(self, client):
        r = client.get("/this-route-does-not-exist")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# system_integrity platform detection — regression for the bug where a
# Linux-collected row rendered under macOS labels (FileVault OFF, …)
# ---------------------------------------------------------------------------


class TestSystemIntegrityPlatform:
    def _sink(self, tmp_path):
        db = tmp_path / "si.db"
        engine = create_engine(
            f"sqlite:///{db}", connect_args={"check_same_thread": False}
        )
        s = Sink(engine)
        s.setup()
        return s

    def _run(self, sink):
        run_id, started = sink.start_run("h", 5)
        return run_id, started

    def test_linux_row_renders_linux_labels(self, tmp_path):
        sink = self._sink(tmp_path)
        run_id, ts = self._run(sink)
        # A Linux collector writes everything into raw_json and leaves
        # the macOS columns at their 0/None defaults.
        sink.write(
            SystemIntegrityRow,
            [
                {
                    "run_id": run_id,
                    "collected_at": ts,
                    "content_hash": "a",
                    "raw_json": '{"selinux": null, "apparmor": {"enabled": true},'
                    ' "ufw_active": true, "firewalld_active": false,'
                    ' "sshd_active": false, "vnc_active": false,'
                    ' "luks_mappings": 1}',
                }
            ],
        )
        with Session(sink.engine) as s:
            si = system_integrity(s, run_id)
        assert si["platform"] == "Linux"
        labels = [name for name, _ in si["rows"]]
        # macOS-only labels must NOT appear for Linux data.
        assert "FileVault" not in labels
        assert "Gatekeeper" not in labels
        # Linux posture must be present and read from raw_json.
        d = dict(si["rows"])
        assert d["AppArmor"] is True
        assert d["Firewall (ufw)"] is True
        assert d["Disk encryption (LUKS)"] is True
        assert d["SSH (sshd)"] is False

    def test_macos_row_renders_macos_labels(self, tmp_path):
        sink = self._sink(tmp_path)
        run_id, ts = self._run(sink)
        # A macOS collector fills the named columns; raw_json has no
        # Linux keys.
        sink.write(
            SystemIntegrityRow,
            [
                {
                    "run_id": run_id,
                    "collected_at": ts,
                    "content_hash": "b",
                    "filevault_active": 1,
                    "gatekeeper_assessments_enabled": 1,
                    "remote_login_enabled": 0,
                    "raw_json": '{"sip": "enabled"}',
                }
            ],
        )
        with Session(sink.engine) as s:
            si = system_integrity(s, run_id)
        assert si["platform"] == "macOS"
        d = dict(si["rows"])
        assert "FileVault" in d
        assert d["FileVault"] == 1
        assert d["Gatekeeper"] == 1
        assert "Disk encryption (LUKS)" not in d  # not a macOS label

    def test_missing_row_returns_none(self, tmp_path):
        sink = self._sink(tmp_path)
        run_id, _ = self._run(sink)
        with Session(sink.engine) as s:
            assert system_integrity(s, run_id) is None


# ---------------------------------------------------------------------------
# WAL visibility — regression for the monitor↔dashboard startup race where
# immutable=1 made the dashboard 500 with "no such table" because the schema
# was still in the -wal, not yet checkpointed into the main .db.
# ---------------------------------------------------------------------------


class TestWalVisibility:
    def test_engine_url_is_not_immutable(self):
        # immutable=1 ignores the WAL — must not be used.
        app.config["DB_PATH"] = "/tmp/whatever.db"
        with app.app_context():
            assert "immutable" not in str(_engine().url)
            assert "mode=ro" in str(_engine().url)

    def test_reads_rows_sitting_in_uncheckpointed_wal(self, tmp_path):
        import sqlite3

        from sqlalchemy import text

        db = tmp_path / "wal.db"
        # Writer in WAL mode; commit data but keep the connection OPEN so
        # the WAL is never checkpointed into the main .db — exactly the
        # state during the monitor's first seconds.
        w = sqlite3.connect(str(db))
        w.execute("PRAGMA journal_mode=WAL")
        w.execute("CREATE TABLE collection_runs (run_id TEXT)")
        w.execute("INSERT INTO collection_runs VALUES ('x')")
        w.commit()
        try:
            app.config["DB_PATH"] = str(db)
            with app.app_context():
                with _engine().connect() as c:
                    n = c.execute(text("SELECT count(*) FROM collection_runs")).scalar()
            # Pre-fix (immutable=1) this raised "no such table".
            assert n == 1
        finally:
            w.close()


class TestLatestRunFallback:
    """latest_run shows a completed run when one exists, else the most
    recent in-progress run — so the dashboard isn't empty for the whole
    first cycle (the recurring 'no run yet' complaint)."""

    def _sink(self, tmp_path):
        engine = create_engine(
            f"sqlite:///{tmp_path/'r.db'}", connect_args={"check_same_thread": False}
        )
        s = Sink(engine)
        s.setup()
        return s

    def test_in_progress_run_shown_when_none_completed(self, tmp_path):
        sink = self._sink(tmp_path)
        sink.start_run("h", 5)  # in-progress, finished_at is NULL
        with Session(sink.engine) as s:
            run = latest_run(s)
        assert run is not None  # not None → dashboard shows it
        assert run.finished_at is None

    def test_prefers_completed_over_newer_in_progress(self, tmp_path):
        sink = self._sink(tmp_path)
        done_id, _ = sink.start_run("h", 5)
        sink.end_run(ok=3, failed=0)  # completed (older)
        sink.run_id = None
        sink.start_run("h", 5)  # newer, in-progress
        with Session(sink.engine) as s:
            run = latest_run(s)
        # Steady state: show the stable completed run, not the empty new one.
        assert run.run_id == done_id
        assert run.finished_at is not None

    def test_none_when_no_runs_at_all(self, tmp_path):
        sink = self._sink(tmp_path)
        with Session(sink.engine) as s:
            assert latest_run(s) is None


# ---------------------------------------------------------------------------
# Cooperative control plane — token auth + control writes
# ---------------------------------------------------------------------------


class TestControlPlane:
    def _state(self):
        from avai.dashboard.control import read_control_state

        with app.app_context():
            return read_control_state()

    def test_fragment_control_renders(self, client):
        r = client.get("/fragments/control")
        assert r.status_code == 200
        assert b"monitor control" in r.data

    def test_panel_survives_missing_control_table(self, client):
        """Belt-and-suspenders: even if control_state is somehow absent, the
        panel degrades to 'offline' (200) instead of 500ing."""
        import sqlite3

        con = sqlite3.connect(app.config["DB_PATH"])
        con.execute("DROP TABLE IF EXISTS control_state")
        con.commit()
        con.close()
        from avai.dashboard.control import read_control_state

        with app.app_context():
            assert read_control_state() is None  # degraded, did not raise
        assert client.get("/fragments/control").status_code == 200

    def test_post_without_token_is_forbidden(self, client, monkeypatch):
        monkeypatch.delenv("AVAI_CONTROL_TOKEN", raising=False)
        # Even supplying a header: fail closed when the server has no token.
        r = client.post("/control/pause", headers={"X-Avai-Token": "x"})
        assert r.status_code == 403

    def test_post_with_wrong_token_is_forbidden(self, client, monkeypatch):
        monkeypatch.setenv("AVAI_CONTROL_TOKEN", "secret")
        r = client.post("/control/pause", headers={"X-Avai-Token": "nope"})
        assert r.status_code == 403

    def test_pause_resume_writes_row(self, client, monkeypatch):
        monkeypatch.setenv("AVAI_CONTROL_TOKEN", "secret")
        h = {"X-Avai-Token": "secret"}
        assert client.post("/control/pause", headers=h).status_code == 200
        assert self._state()["paused"] == 1
        assert client.post("/control/resume", headers=h).status_code == 200
        assert self._state()["paused"] == 0

    def test_scan_now_bumps_nonce(self, client, monkeypatch):
        monkeypatch.setenv("AVAI_CONTROL_TOKEN", "secret")
        h = {"X-Avai-Token": "secret"}
        before = self._state()
        before_nonce = before["scan_now_nonce"] if before else 0
        client.post("/control/scan-now", headers=h)
        assert self._state()["scan_now_nonce"] == before_nonce + 1

    def test_collector_toggle(self, client, monkeypatch):
        monkeypatch.setenv("AVAI_CONTROL_TOKEN", "secret")
        h = {"X-Avai-Token": "secret"}
        client.post("/control/collector/network_flows/off", headers=h)
        assert "network_flows" in (self._state()["disabled_collectors"] or "")
        client.post("/control/collector/network_flows/on", headers=h)
        assert "network_flows" not in (self._state()["disabled_collectors"] or "")

    def test_unknown_collector_is_rejected(self, client, monkeypatch):
        monkeypatch.setenv("AVAI_CONTROL_TOKEN", "secret")
        r = client.post(
            "/control/collector/bogus/off", headers={"X-Avai-Token": "secret"}
        )
        assert r.status_code == 400

    def test_settings_update(self, client, monkeypatch):
        monkeypatch.setenv("AVAI_CONTROL_TOKEN", "secret")
        h = {"X-Avai-Token": "secret"}
        client.post(
            "/control/settings",
            headers=h,
            data={"interval": "45", "judge": "0", "enrich": "1"},
        )
        st = self._state()
        assert st["interval_override"] == 45
        assert st["judge_enabled"] == 0 and st["enrich_enabled"] == 1

    def test_maintenance_queues_command(self, client, monkeypatch):
        monkeypatch.setenv("AVAI_CONTROL_TOKEN", "secret")
        h = {"X-Avai-Token": "secret"}
        client.post("/control/maintenance/prune", headers=h)
        st = self._state()
        assert st["command"] == "prune" and st["command_nonce"] == 1

    def test_unknown_maintenance_action_is_rejected(self, client, monkeypatch):
        monkeypatch.setenv("AVAI_CONTROL_TOKEN", "secret")
        r = client.post(
            "/control/maintenance/bogus", headers={"X-Avai-Token": "secret"}
        )
        assert r.status_code == 400
