"""The board's Setup, Host, Activity, Network and Collection panels, and the
blueprint that registers every board route."""

from __future__ import annotations

from typing import Any

from flask import Blueprint
from sqlalchemy.orm import Session

from ..queries import (
    DiskOrder,
    DnsPanel,
    DnsQuery,
    FlowQuery,
    FlowsPanel,
    IntegrityPosture,
    Page,
    PortQuery,
    PortsPanel,
    ResourceQueries,
    RunQueries,
    StoredJson,
    YaraPanels,
)
from ..queries.board_activity import ActivityStreams, ExecFeed
from ..queries.board_host import HostTrend, SvgBox
from ..control import ControlReader
from ..queries.board_status import (
    AccessCheck,
    JudgeTotals,
    LookupSources,
    SecondPassSwitch,
)
from . import DashboardServices
from .board import (
    AlertsFragment,
    BoardIndex,
    BoardView,
    ChangesFragment,
    FeedbackAnswer,
    FindingsFragment,
    IncidentFragment,
    InspectFragment,
    ThreatStatsFragment,
    TopbarFragment,
    VulnInspectFragment,
)
from .fragments import RowCountsView

RATE_MINUTES = 20
FEED_ROWS = 12
PORTS_SHOWN = 8
DESTINATIONS_SHOWN = 4
DOMAINS_SHOWN = 6
RUNS_SHOWN = 8
ROW_COUNTS_SHOWN = 8
# The CPU chart is drawn into a 600 x 160 box, percentages on a 0-100 scale.
CHART_WIDTH = 600
CHART_HEIGHT = 160
PERCENT_TOP = 100
# The load sparkline: 120 x 50, never scaled below a load of 1.
SPARK_WIDTH = 120
SPARK_HEIGHT = 50
LOAD_TOP = 1


class SetupFragment(BoardView):
    TEMPLATE = "board/_setup.html"

    def context(self, session: Session) -> dict[str, Any]:
        state = ControlReader().read(session) or {}
        caps = StoredJson().as_dict(state.get("capabilities_json"))
        return {
            "monitor": self.monitor(session),
            "caps": caps,
            "control_state": state,
            "second_pass": SecondPassSwitch(caps, state),
            "judge": JudgeTotals(session).fields(),
            "refused": AccessCheck(session).refused(),
            "sources": LookupSources(session).names(),
            **self.control_flags(),
        }


class HostFragment(BoardView):
    TEMPLATE = "board/_host.html"

    def context(self, session: Session) -> dict[str, Any]:
        latest = RunQueries(session).latest_run()
        resources = ResourceQueries(session)
        disks = resources.disk_usage(latest.run_id) if latest else []
        trend = HostTrend(session).series()
        return {
            "resources": resources.host_resources(latest.run_id) if latest else None,
            "disks": DiskOrder().primary(disks),
            "trend": trend,
            "cpu_points": SvgBox(CHART_WIDTH, CHART_HEIGHT, PERCENT_TOP).points(
                trend["cpu"]
            ),
            "load_points": SvgBox(SPARK_WIDTH, SPARK_HEIGHT, LOAD_TOP).points(
                trend["load"]
            ),
        }


class RatesFragment(BoardView):
    TEMPLATE = "board/_rates.html"

    def context(self, session: Session) -> dict[str, Any]:
        streams = ActivityStreams()
        return {
            "exec_rate": streams.exec_rate(session, RATE_MINUTES),
            "auth_rate": streams.auth_rate(session, RATE_MINUTES),
        }


class ExecFeedFragment(BoardView):
    TEMPLATE = "board/_exec_feed.html"

    def context(self, session: Session) -> dict[str, Any]:
        return {
            "rows": ExecFeed(session).latest(FEED_ROWS),
            "refused": AccessCheck(session).refused(),
        }


class PortsFragment(BoardView):
    TEMPLATE = "board/_ports.html"

    def context(self, session: Session) -> dict[str, Any]:
        latest = RunQueries(session).latest_run()
        if latest is None:
            return {"ports": None}
        query = PortQuery(page=Page(1, PORTS_SHOWN))
        return {"ports": PortsPanel(session, latest.run_id).ports(query)}


class NetworkFragment(BoardView):
    TEMPLATE = "board/_network.html"

    def context(self, session: Session) -> dict[str, Any]:
        latest = RunQueries(session).latest_run()
        if latest is None:
            return {"flows": None, "dns": None, "sysint": None}
        run_id = latest.run_id
        flows = FlowsPanel(session, run_id).flows(
            FlowQuery(page=Page(1, DESTINATIONS_SHOWN))
        )
        dns = DnsPanel(session, run_id).queries(DnsQuery(page=Page(1, DOMAINS_SHOWN)))
        return {
            "flows": flows,
            "dns": dns,
            "sysint": IntegrityPosture(session).for_run(run_id),
        }


class CollectionFragment(BoardView):
    TEMPLATE = "board/_collection.html"

    def context(self, session: Session) -> dict[str, Any]:
        return {
            "runs": RunQueries(session).recent_runs(RUNS_SHOWN),
            "row_counts": RowCountsView(session).for_latest()[:ROW_COUNTS_SHOWN],
            "yara": YaraPanels(session).status(),
            "refused": AccessCheck(session).refused(),
        }


class BoardRoutes:
    """The ``board`` blueprint: (path, endpoint, view) per panel."""

    ROUTES = (
        ("/", "board_index", BoardIndex),
        ("/board/topbar", "board_topbar", TopbarFragment),
        ("/board/setup", "board_setup", SetupFragment),
        ("/board/threat-stats", "board_threat_stats", ThreatStatsFragment),
        ("/board/alerts", "board_alerts", AlertsFragment),
        ("/board/changes", "board_changes", ChangesFragment),
        ("/board/incident", "board_incident", IncidentFragment),
        ("/board/findings", "board_findings", FindingsFragment),
        ("/board/inspect/<collector>/<content_hash>", "board_inspect", InspectFragment),
        ("/board/inspect-vuln", "board_inspect_vuln", VulnInspectFragment),
        (
            "/board/feedback/<collector>/<content_hash>/<label>",
            "board_feedback",
            FeedbackAnswer,
        ),
        ("/board/host", "board_host", HostFragment),
        ("/board/rates", "board_rates", RatesFragment),
        ("/board/exec-feed", "board_exec_feed", ExecFeedFragment),
        ("/board/ports", "board_ports", PortsFragment),
        ("/board/network", "board_network", NetworkFragment),
        ("/board/collection", "board_collection", CollectionFragment),
    )

    def __init__(self, services: DashboardServices) -> None:
        self._services = services

    def blueprint(self) -> Blueprint:
        blueprint = Blueprint("board", __name__)
        for path, endpoint, view in self.ROUTES:
            blueprint.add_url_rule(
                path, view_func=view.as_view(endpoint, self._services)
            )
        return blueprint
