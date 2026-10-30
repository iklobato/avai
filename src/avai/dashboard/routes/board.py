"""The panels board: the page at ``/`` and one fragment per panel under
``/board/``. The previous page stays at ``/classic`` with its own fragments,
so nothing here changes what those render."""

from __future__ import annotations

from http import HTTPStatus
from typing import Any, ClassVar

from flask import abort, render_template, request
from sqlalchemy.orm import Session

from avai.host_monitor import FeedbackLabel

from ..control import ControlReader, Feedback, MonitorLiveness
from ..queries import (
    CollectorTables,
    Page,
    ReportQueries,
    RunQueries,
    StoredJson,
    VerdictQueries,
    VulnerabilitiesPanel,
    VulnQuery,
)
from ..queries.board_findings import CollectorLabels, FeedbackLabels, FindingInspector
from ..queries.board_host import VulnInspector
from ..queries.board_status import (
    AccessCheck,
    ActiveVerdicts,
    JudgeTotals,
    MonitorState,
    NovelFindings,
    PersistenceChanges,
)
from ..queries.findings import FindingFilter, FindingsPanel, FindingsQuery
from . import ServiceView
from .control import TokenGate

TOP_VULNERABILITIES = 3
ALERTS_SHOWN = 5
FINDINGS_SHOWN = 8


class BoardView(ServiceView):
    """A GET panel that renders ``TEMPLATE`` with what ``context`` returns."""

    methods: ClassVar[list[str]] = ["GET"]
    TEMPLATE: ClassVar[str]

    def dispatch_request(self) -> str:
        with self._services.read_session() as session:
            return render_template(self.TEMPLATE, **self.context(session))

    def context(self, session: Session) -> dict[str, Any]:
        raise NotImplementedError

    def control_flags(self) -> dict[str, bool]:
        config = self._services.config
        return {
            "control_enabled": config.control_enabled,
            "control_open": config.control_open,
        }

    def monitor(self, session: Session) -> MonitorState:
        state = ControlReader().read(session)
        return MonitorState(MonitorLiveness(self._services.clock).alive(state), state)


class BoardIndex(BoardView):
    TEMPLATE = "board.html"

    def context(self, session: Session) -> dict[str, Any]:
        return {"app_mode": self._services.config.app_mode, **self.control_flags()}


class TopbarFragment(BoardView):
    TEMPLATE = "board/_topbar.html"

    def context(self, session: Session) -> dict[str, Any]:
        latest = RunQueries(session).latest_run()
        monitor = self.monitor(session)
        since = request.args.get("since", "")
        needs = int(not monitor.alive) + int(bool(AccessCheck(session).refused()))
        return {
            "host": latest.hostname if latest else "this computer",
            "monitor": monitor,
            "last_run": latest,
            "new_alerts": len(VerdictQueries(session).new_alerts(since or None)),
            "needs": needs,
        }


class ThreatStatsFragment(BoardView):
    TEMPLATE = "board/_threat_stats.html"

    def context(self, session: Session) -> dict[str, Any]:
        vulns = VulnerabilitiesPanel(session).vulnerabilities(
            VulnQuery(page=Page(1, TOP_VULNERABILITIES))
        )
        return {
            "counts": ActiveVerdicts(session).counts(),
            "risk": ReportQueries(session).latest_risk(),
            "vulns": vulns,
            "judge": JudgeTotals(session).fields(),
        }


class AlertsFragment(BoardView):
    TEMPLATE = "board/_alerts.html"

    def context(self, session: Session) -> dict[str, Any]:
        since = request.args.get("since", "")
        alerts = VerdictQueries(session).new_alerts(since or None)
        return {
            "alerts": alerts[:ALERTS_SHOWN],
            "total": len(alerts),
            "now": self._services.clock.now_iso(),
        }


class ChangesFragment(BoardView):
    TEMPLATE = "board/_changes.html"

    def context(self, session: Session) -> dict[str, Any]:
        return {
            "changes": PersistenceChanges(session).rows(),
            "novel": NovelFindings(session).collectors(),
        }


class IncidentFragment(BoardView):
    TEMPLATE = "board/_incident.html"

    def context(self, session: Session) -> dict[str, Any]:
        row = ReportQueries(session).latest_narrative()
        actions = StoredJson().as_list(row.actions_json) if row else []
        return {"narrative": row, "actions": actions}


class FindingsFragment(BoardView):
    TEMPLATE = "board/_findings.html"

    def context(self, session: Session) -> dict[str, Any]:
        query = FindingsQuery(filters=FindingFilter(), page=Page(1, FINDINGS_SHOWN))
        found = FindingsPanel(session).findings(query)
        keys = [(item["collector"], item["content_hash"]) for item in found["items"]]
        return {
            "found": found,
            "answers": FeedbackLabels(session).for_keys(keys),
            "labels": CollectorLabels(),
            **self.control_flags(),
        }


class InspectFragment(ServiceView):
    methods: ClassVar[list[str]] = ["GET"]

    def dispatch_request(self, collector: str, content_hash: str) -> str:
        with self._services.read_session() as session:
            detail = FindingInspector(session).detail(collector, content_hash)
            if detail is None:
                abort(HTTPStatus.NOT_FOUND)
            return render_template("board/_inspect.html", item=detail)


class VulnInspectFragment(BoardView):
    TEMPLATE = "board/_inspect.html"

    def context(self, session: Session) -> dict[str, Any]:
        detail = VulnInspector(session).detail(request.args.get("software", ""))
        if detail is None:
            abort(HTTPStatus.NOT_FOUND)
        return {"item": detail}


class FeedbackAnswer(ServiceView):
    """Save 'real problem' or 'this is normal' for one finding and return the
    cell that shows the saved answer. The monitor applies it next cycle."""

    methods: ClassVar[list[str]] = ["POST"]

    def dispatch_request(self, collector: str, content_hash: str, label: str) -> str:
        TokenGate(self._services).check()
        if CollectorTables().model(collector) is None or label not in tuple(
            FeedbackLabel
        ):
            abort(HTTPStatus.BAD_REQUEST)
        answer = Feedback(content_hash, collector, FeedbackLabel(label), None, None)
        self._services.control.record_feedback(answer)
        return render_template("board/_answer.html", answer=label)
