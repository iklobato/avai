"""The panels board: every new route answers on an empty DB, and the panels
built from seeded rows show what the database really holds."""

from __future__ import annotations

import json
from http import HTTPStatus
from pathlib import Path

import pytest
from flask.testing import FlaskClient
from sqlalchemy import create_engine, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from avai.dashboard.app import DashboardApp
from avai.dashboard.config import DashboardConfig
from avai.dashboard.queries.board_activity import ActivityStreams, MinuteStamp
from avai.dashboard.queries.board_findings import FindingInspector
from avai.dashboard.queries.board_status import (
    AccessCheck,
    ActiveVerdicts,
    PersistenceChanges,
)
from avai.dashboard.serve import DashboardSchema
from avai.enrichers.cache import EnrichmentSchema
from avai.host_monitor import (
    AuthEventRow,
    Base,
    CollectionRun,
    CollectorErrorRow,
    ControlState,
    DnsQueryRow,
    FeedbackRow,
    Judgement,
    LaunchItemRow,
    ProcessExecRow,
)

TOKEN = "board-test-token"
PLAIN_FIX = "Remove the item that starts this program when you log in."
OLD_RUN = "2026-06-29T23:18:56+00:00"
NEW_RUN = "2026-06-30T00:35:10+00:00"
LOOKBACK_MIN = 5
RATE_MINUTES = 20
HIGH_CONFIDENCE = 0.95
EVIDENCE_CONFIDENCE = 0.9
DOUBLE_CHECK_STEP = 3
ITEMS_BEFORE = 2
ITEMS_AFTER = 3
MINUTES_BACK = 19
LOGINS_LAST_MINUTE = 2
DOMAIN = "evil-domain.com"
DNS_FINDING_STEPS = (
    "2026-06-29",
    "1 records",
    "malicious, possible",
    "not recorded",
    "waiting for you",
)
LOGIN_STAMPS = (
    "2026-06-29 21:48:59.1-0300",
    "2026-06-29 21:49:01.2-0300",
    "2026-06-29 21:49:47.0-0300",
)
BOARD_GETS = (
    "/",
    "/board/topbar",
    "/board/setup",
    "/board/threat-stats",
    "/board/alerts",
    "/board/changes",
    "/board/incident",
    "/board/findings",
    "/board/host",
    "/board/rates",
    "/board/exec-feed",
    "/board/ports",
    "/board/network",
    "/board/collection",
)


class BoardDb:
    """A real SQLite file with the dashboard schema, seeded row by row."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def engine(self) -> Engine:
        return create_engine(f"sqlite:///{self.path}")

    def add(self, rows: list[object]) -> None:
        with Session(self.engine()) as session:
            session.add_all(rows)
            session.commit()

    def runs(self) -> None:
        self.add(
            [
                Rows().collection_round("old", OLD_RUN),
                Rows().collection_round("new", NEW_RUN),
            ]
        )

    def client(self, control_token: str = "") -> FlaskClient:
        config = DashboardConfig(db_path=str(self.path), control_token=control_token)
        app = DashboardApp(config).build()
        app.config["TESTING"] = True
        return app.test_client()


class Rows:
    """One table row each, with only the columns a test cares about."""

    def collection_round(self, run_id: str, started: str) -> CollectionRun:
        return CollectionRun(
            run_id=run_id, started_at=started, hostname="mac", lookback_min=LOOKBACK_MIN
        )

    def judgement(
        self, collector: str, digest: str, fields: dict[str, object] | None = None
    ) -> Judgement:
        values = {"verdict": "malicious", "model": "m", "created_at": OLD_RUN}
        values = {**values, "last_seen_at": NEW_RUN, **(fields or {})}
        return Judgement(collector=collector, content_hash=digest, **values)

    def evidence(self, value: str) -> object:
        model = EnrichmentSchema(Base).model()
        return model(
            source="urlhaus",
            indicator_type="domain",
            indicator_value=value,
            verdict_hint="malicious",
            confidence=EVIDENCE_CONFIDENCE,
            summary="listed",
            details_json="{}",
            fetched_at=NEW_RUN,
        )

    def lookup(self, digest: str, qname: str) -> DnsQueryRow:
        return DnsQueryRow(
            run_id="new", collected_at=NEW_RUN, content_hash=digest, qname=qname
        )

    def login(self, stamp: str) -> AuthEventRow:
        return AuthEventRow(run_id="r", collected_at=NEW_RUN, event_timestamp=stamp)

    def program_start(self, stamp: str) -> ProcessExecRow:
        return ProcessExecRow(
            run_id="r", collected_at=NEW_RUN, event_timestamp=stamp, pid=1
        )

    def launch_items(self, run_id: str, count: int) -> list[LaunchItemRow]:
        return [
            LaunchItemRow(
                run_id=run_id,
                path=f"/{run_id}/{index}",
                scope="user",
                collected_at=NEW_RUN,
            )
            for index in range(count)
        ]

    def caps_without_ai(self) -> dict[str, object]:
        """A monitor started with no AI key and no second passes."""
        return {
            **self._caps(),
            "judge_model": None,
            "verify": False,
            "investigate": False,
        }

    def caps_with_passes(self) -> dict[str, object]:
        """A monitor started with the judge and both second passes."""
        return {
            **self._caps(),
            "judge_model": "claude-haiku-4-5",
            "verify": True,
            "investigate": True,
        }

    def _caps(self) -> dict[str, object]:
        missing = [{"name": "virustotal", "key": "VT_API_KEY"}]
        return {
            "sources_on": ["osv"],
            "sources_missing_key": missing,
            "as_root": False,
            "telemetry_on": False,
        }

    def control(self, capabilities: dict[str, object]) -> ControlState:
        return ControlState(id=1, capabilities_json=json.dumps(capabilities))

    def refusal(self, run_id: str, collector: str) -> CollectorErrorRow:
        return CollectorErrorRow(
            run_id=run_id,
            collector=collector,
            error_class="PermissionError",
            occurred_at=NEW_RUN,
        )


@pytest.fixture
def board(tmp_path: Path) -> BoardDb:
    db = tmp_path / "board.db"
    DashboardSchema().ensure(str(db))
    return BoardDb(db)


class TestBoardRoutes:
    @pytest.mark.parametrize("path", BOARD_GETS)
    def test_every_board_route_answers_on_an_empty_db(
        self, board: BoardDb, path: str
    ) -> None:
        response = board.client().get(path)
        assert response.status_code == HTTPStatus.OK, path

    def test_root_is_the_board_and_the_old_page_moved_to_classic(
        self, board: BoardDb
    ) -> None:
        client = board.client()
        assert b"board.css" in client.get("/").data
        assert b"<title>avai host monitor</title>" in client.get("/classic").data

    def test_inspect_of_an_unknown_finding_is_404(self, board: BoardDb) -> None:
        client = board.client()
        finding = client.get("/board/inspect/processes/nope")
        vulnerability = client.get("/board/inspect-vuln?software=nope@1")
        assert finding.status_code == HTTPStatus.NOT_FOUND
        assert vulnerability.status_code == HTTPStatus.NOT_FOUND


class TestActiveVerdicts:
    def test_only_findings_still_present_are_counted(self, board: BoardDb) -> None:
        board.runs()
        gone = {"verdict": "suspicious", "last_seen_at": OLD_RUN}
        rows = Rows()
        board.add(
            [
                rows.judgement("processes", "here"),
                rows.judgement("processes", "gone", gone),
            ]
        )
        with Session(board.engine()) as session:
            counts = ActiveVerdicts(session).counts()
        assert counts == {"malicious": 1, "suspicious": 0, "unknown": 0, "benign": 0}


class TestFindingInspector:
    def test_evidence_is_linked_through_the_findings_own_indicators(
        self, board: BoardDb
    ) -> None:
        board.runs()
        rows = Rows()
        finding = rows.judgement(
            "dns_queries", "d1", {"reasoning": "Repeated lookups."}
        )
        board.add([rows.lookup("d1", DOMAIN), finding, rows.evidence(DOMAIN)])
        with Session(board.engine()) as session:
            detail = FindingInspector(session).detail("dns_queries", "d1")
        assert [answer["source"] for answer in detail["evidence"]] == ["urlhaus"]
        assert detail["area"] == "web addresses it looks up"
        outcomes = [step["outcome"] for step in detail["steps"]]
        assert outcomes == list(DNS_FINDING_STEPS)

    def test_a_verdict_the_skeptic_lowered_says_so_without_the_marker(
        self, board: BoardDb
    ) -> None:
        board.runs()
        reasoning = "[verifier downgraded malicious→suspicious] Signed by Apple."
        fields = {"verdict": "suspicious", "reasoning": reasoning}
        board.add(
            [
                Rows().judgement(
                    "processes", "p1", {**fields, "confidence": HIGH_CONFIDENCE}
                )
            ]
        )
        with Session(board.engine()) as session:
            detail = FindingInspector(session).detail("processes", "p1")
        assert detail["steps"][DOUBLE_CHECK_STEP]["outcome"] == "lowered"
        assert detail["title"] == "Signed by Apple."


class TestFeedbackAnswer:
    def test_answer_is_saved_with_the_token(self, board: BoardDb) -> None:
        board.runs()
        board.add([Rows().judgement("processes", "p1")])
        client = board.client(control_token=TOKEN)
        path = "/board/feedback/processes/p1/false_positive"
        response = client.post(path, headers={"X-Avai-Token": TOKEN})
        assert response.status_code == HTTPStatus.OK
        assert b"Saved: normal for me" in response.data
        with Session(board.engine()) as session:
            saved = session.execute(select(FeedbackRow.label)).scalars().all()
        assert saved == ["false_positive"]

    def test_answer_without_the_token_is_refused(self, board: BoardDb) -> None:
        client = board.client(control_token=TOKEN)
        response = client.post("/board/feedback/processes/p1/confirmed")
        assert response.status_code == HTTPStatus.FORBIDDEN

    def test_unknown_label_is_a_bad_request(self, board: BoardDb) -> None:
        client = board.client(control_token=TOKEN)
        path = "/board/feedback/processes/p1/maybe"
        response = client.post(path, headers={"X-Avai-Token": TOKEN})
        assert response.status_code == HTTPStatus.BAD_REQUEST


class TestStreamRate:
    def test_each_stream_is_counted_in_its_own_time_format(
        self, board: BoardDb
    ) -> None:
        rows = Rows()
        logins = [rows.login(stamp) for stamp in LOGIN_STAMPS]
        board.add([*logins, rows.program_start("2026-06-17T16:19:59.5Z")])
        with Session(board.engine()) as session:
            auth = ActivityStreams().auth_rate(session, RATE_MINUTES)
            execs = ActivityStreams().exec_rate(session, RATE_MINUTES)
        auth_bars = [(minute["clock"], minute["count"]) for minute in auth["bars"]]
        busy = [(clock, count) for clock, count in auth_bars if count]
        assert busy == [("21:48", 1), ("21:49", LOGINS_LAST_MINUTE)]
        assert auth["first"] == "2026-06-29 21:30"
        assert [minute["count"] for minute in execs["bars"]][-1] == 1

    def test_quiet_minutes_get_an_empty_bar_so_gaps_stay_visible(
        self, board: BoardDb
    ) -> None:
        # Regression: only minutes with events got a bar, so 23:07 and 23:26
        # were drawn side by side as if they were one minute apart.
        rows = Rows()
        board.add(
            [
                rows.login("2026-10-29 23:07:01.0-0300"),
                rows.login("2026-10-29 23:26:30.0-0300"),
            ]
        )
        with Session(board.engine()) as session:
            bars = ActivityStreams().auth_rate(session, RATE_MINUTES)["bars"]
        assert len(bars) == RATE_MINUTES
        assert [minute["clock"] for minute in bars if minute["count"]] == [
            "23:07",
            "23:26",
        ]
        assert bars[0]["clock"] == "23:07"

    def test_the_window_crosses_midnight(self) -> None:
        moved = MinuteStamp("2026-06-30 00:05").minus(MINUTES_BACK)
        assert moved.text == "2026-06-29 23:46"


class TestPersistenceChanges:
    def test_before_and_after_come_from_the_two_latest_runs(
        self, board: BoardDb
    ) -> None:
        board.runs()
        rows = Rows()
        board.add(
            [
                *rows.launch_items("old", ITEMS_BEFORE),
                *rows.launch_items("new", ITEMS_AFTER),
            ]
        )
        with Session(board.engine()) as session:
            items = PersistenceChanges(session).rows()["items"]
        launch = next(item for item in items if item["name"] == "launch_items")
        expected = {"before": ITEMS_BEFORE, "after": ITEMS_AFTER, "delta": 1}
        assert launch == {"name": "launch_items", **expected}


class TestAccessCheck:
    def test_permission_errors_in_the_latest_run_mean_no_full_access(
        self, board: BoardDb
    ) -> None:
        board.runs()
        rows = Rows()
        board.add(
            [rows.refusal("new", "listening_ports"), rows.refusal("old", "processes")]
        )
        with Session(board.engine()) as session:
            assert AccessCheck(session).refused() == ["listening_ports"]
        assert b"Not given" in board.client().get("/board/setup").data


class TestCollectionPanel:
    def test_a_round_still_running_is_not_shown_as_zero_ok(
        self, board: BoardDb
    ) -> None:
        # Regression: a round with no finished_at read "0 ok", like a failure.
        board.runs()
        page = board.client().get("/board/collection").data
        assert b"not finished" in page
        assert b"0 ok" not in page


class TestPhase2Inspect:
    def test_a_stored_agreement_and_the_plain_fix_are_shown(
        self, board: BoardDb
    ) -> None:
        board.runs()
        fields = {"verify_outcome": "agreed", "remediation_plain": PLAIN_FIX}
        board.add([Rows().judgement("processes", "p1", fields)])
        page = board.client().get("/board/inspect/processes/p1").data.decode()
        assert "agreed" in page
        assert PLAIN_FIX in page


class TestPhase2Setup:
    def test_the_monitor_snapshot_drives_the_cards(self, board: BoardDb) -> None:
        board.add([Rows().control(Rows().caps_without_ai())])
        page = board.client(control_token=TOKEN).get("/board/setup").data.decode()
        assert "nothing gets judged" in page
        assert "Off since avai started" in page
        assert "virustotal" in page
        assert 'role="switch" aria-checked="true" aria-label="Double-check"' not in page

    def test_the_double_check_switch_saves_off(self, board: BoardDb) -> None:
        board.add([Rows().control(Rows().caps_with_passes())])
        client = board.client(control_token=TOKEN)
        assert 'aria-label="Double-check"' in client.get("/board/setup").data.decode()
        form = {"verify": "off", "investigate": "off"}
        client.post("/control/settings", data=form, headers={"X-Avai-Token": TOKEN})
        with Session(board.engine()) as session:
            row = session.get(ControlState, 1)
            assert (row.verify_enabled, row.investigate_enabled) == (0, 0)
        assert "Off" in client.get("/board/setup").data.decode()
