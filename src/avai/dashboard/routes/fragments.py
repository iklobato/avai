"""HTML fragments the dashboard page polls, one view class per panel."""

from __future__ import annotations

from typing import Any, ClassVar

from flask import Blueprint, render_template, request
from flask.views import View
from sqlalchemy.orm import Session

from avai.host_monitor.enums import Verdict

from ..control import ControlReader, MonitorLiveness
from ..queries import (
    DEFAULT_PER_PAGE,
    PER_PAGE_OPTIONS,
    AuthEventsPanel,
    AuthQuery,
    DiskOrder,
    DnsPanel,
    DnsQuery,
    FindingFilter,
    FindingStatus,
    FindingOptions,
    FindingsPanel,
    FindingsQuery,
    FlowQuery,
    FlowsPanel,
    IntegrityPosture,
    LogAggregateQuery,
    LogFilter,
    LogQuery,
    LogsPanel,
    MountTree,
    NetworkPanels,
    Page,
    PersistencePages,
    PersistencePanel,
    PortQuery,
    PortsPanel,
    ReportQueries,
    ResourceQueries,
    RowCounts,
    RowFilter,
    RunMark,
    RunQueries,
    StoredJson,
    VerdictQueries,
    VulnerabilitiesPanel,
    VulnQuery,
    YaraPanels,
)
from . import ServiceLookup


class RequestArgs:
    """The query-string values a fragment reads."""

    def text(self, name: str, default: str = "") -> str:
        return request.args.get(name, default)

    def number(self, name: str, default: int) -> int:
        try:
            return int(request.args.get(name, ""))
        except (TypeError, ValueError):
            return default

    def page(self, name: str = "page") -> Page:
        return Page(self.number(name, 1), self.number("per_page", DEFAULT_PER_PAGE))

    def row_filter(self) -> RowFilter:
        return RowFilter(self.text("verdict"), self.text("q"))


class Sparkline:
    """SVG polyline points for a 0-100 score series (oldest to newest)."""

    WIDTH = 140
    HEIGHT = 30
    PAD = 3
    MAX_SCORE = 100
    # The padding applies on both edges of each axis.
    PADDED_EDGES = 2

    def points(self, scores: list[int]) -> str:
        if not scores:
            return ""
        series = scores if len(scores) > 1 else scores + scores
        step = (self.WIDTH - self.PADDED_EDGES * self.PAD) / (len(series) - 1)
        return " ".join(
            f"{self.PAD + index * step:.1f},{self._y(score):.1f}"
            for index, score in enumerate(series)
        )

    def _y(self, score: int) -> float:
        share = max(0, min(self.MAX_SCORE, score)) / self.MAX_SCORE
        return (self.HEIGHT - self.PAD) - share * (
            self.HEIGHT - self.PADDED_EDGES * self.PAD
        )


class RiskView:
    """The risk score fields the triage, risk and posture panels share."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def fields(self) -> dict[str, Any]:
        reports = ReportQueries(self._session)
        row = reports.latest_risk()
        trend = reports.risk_trend()
        return {
            "risk": row,
            "drivers": StoredJson().as_list(row.drivers_json) if row else [],
            "spark_points": Sparkline().points(trend),
            "trend_len": len(trend),
        }


class StaticFragment(View):
    """A panel that renders a fixed template (its tabs lazy-load the rest)."""

    methods: ClassVar[list[str]] = ["GET"]
    TEMPLATE: ClassVar[str]

    def dispatch_request(self) -> str:
        return render_template(self.TEMPLATE)


class LatestRunFragment(View):
    """A panel built from the latest run; ``EMPTY`` when there is none."""

    methods: ClassVar[list[str]] = ["GET"]
    TEMPLATE: ClassVar[str]
    KEY: ClassVar[str]
    EMPTY: ClassVar[Any] = None

    def dispatch_request(self) -> str:
        with ServiceLookup().read_session() as session:
            latest = RunQueries(session).latest_run()
            value = self.EMPTY if latest is None else self.build(session, latest.run_id)
            context = {self.KEY: value, "per_page_options": PER_PAGE_OPTIONS}
            return render_template(self.TEMPLATE, **context)

    def build(self, session: Session, run_id: str) -> Any:
        raise NotImplementedError


class IndexView(View):
    methods: ClassVar[list[str]] = ["GET"]

    def dispatch_request(self) -> str:
        app_mode = ServiceLookup().services().config.app_mode
        return render_template("dashboard.html", app_mode=app_mode)


class TriageFragment(View):
    """Above-the-fold triage strip: posture grade, active malicious /
    suspicious finding counts, and monitor liveness."""

    methods: ClassVar[list[str]] = ["GET"]

    def dispatch_request(self) -> str:
        lookup = ServiceLookup()
        with lookup.read_session() as session:
            state = ControlReader().read(session)  # for both alive and the ctrl chips
            risk = RiskView(session).fields()
            return render_template(
                "partials/_triage.html",
                risk=risk["risk"],
                active_malicious=self._active(session, Verdict.MALICIOUS),
                active_suspicious=self._active(session, Verdict.SUSPICIOUS),
                alive=MonitorLiveness().alive(state),
                ctrl=state,
                latest_run=RunQueries(session).latest_run(),
                drivers=risk["drivers"],
                app_mode=lookup.services().config.app_mode,
            )

    def _active(self, session: Session, verdict: Verdict) -> int:
        query = FindingsQuery(filters=FindingFilter(verdict=verdict), page=Page(1, 1))
        return FindingsPanel(session).findings(query)["total"]


class HeaderMetaFragment(View):
    methods: ClassVar[list[str]] = ["GET"]

    def dispatch_request(self) -> str:
        with ServiceLookup().read_session() as session:
            latest = RunQueries(session).latest_run()
            return render_template("partials/_header_meta.html", latest_run=latest)


class OverviewFragment(View):
    methods: ClassVar[list[str]] = ["GET"]

    def dispatch_request(self) -> str:
        with ServiceLookup().read_session() as session:
            runs, verdicts = RunQueries(session), VerdictQueries(session)
            latest = runs.latest_run()
            started = latest.started_at if latest else None
            return render_template(
                "partials/_overview.html",
                latest_run=latest,
                runs_total=runs.runs_total(),
                verdict_counts=verdicts.verdict_counts(),
                judged_this_run=verdicts.judged_since(started) if started else 0,
                cost_this_run=verdicts.cost_since(started) if started else 0.0,
            )


class RiskFragment(View):
    methods: ClassVar[list[str]] = ["GET"]

    def dispatch_request(self) -> str:
        with ServiceLookup().read_session() as session:
            return render_template("partials/_risk.html", **RiskView(session).fields())


class IncidentFragment(View):
    methods: ClassVar[list[str]] = ["GET"]

    def dispatch_request(self) -> str:
        with ServiceLookup().read_session() as session:
            row = ReportQueries(session).latest_narrative()
            parse = StoredJson()
            return render_template(
                "partials/_incident.html",
                narrative=row,
                timeline=parse.as_list(row.timeline_json) if row else [],
                actions=parse.as_list(row.actions_json) if row else [],
            )


class VerdictsFragment(StaticFragment):
    """Verdicts panel: last-12h activity trend. Cumulative totals live in the
    overview donut, so this panel no longer duplicates them."""

    TEMPLATE = "partials/_verdicts.html"


class NetworkFragment(StaticFragment):
    """Tabbed network panel wrapper (tabs lazy-load the other fragments)."""

    TEMPLATE = "partials/_network.html"


class PostureFragment(View):
    """Merged posture panel: risk score + system-integrity checklist."""

    methods: ClassVar[list[str]] = ["GET"]

    def dispatch_request(self) -> str:
        with ServiceLookup().read_session() as session:
            latest = RunQueries(session).latest_run()
            sysint = (
                IntegrityPosture(session).for_run(latest.run_id) if latest else None
            )
            return render_template(
                "partials/_posture.html", **RiskView(session).fields(), sysint=sysint
            )


class CollectionFragment(View):
    """Merged collection-health panel: row counts + recent runs + errors."""

    methods: ClassVar[list[str]] = ["GET"]

    def dispatch_request(self) -> str:
        with ServiceLookup().read_session() as session:
            runs = RunQueries(session)
            latest = runs.latest_run()
            return render_template(
                "partials/_collection.html",
                recent_runs=runs.recent_runs(),
                errors=runs.collector_errors(latest.run_id) if latest else [],
                row_counts=RowCountsView(session).for_latest(),
            )


class RowCountsView:
    """Row counts for the latest run against the run before it."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def for_latest(self) -> list[dict[str, Any]]:
        runs = RunQueries(self._session)
        latest = runs.latest_run()
        if latest is None:
            return []
        previous = RunMark(*runs.prior_run(latest.started_at))
        current = RunMark(latest.run_id, latest.started_at)
        return RowCounts(self._session).for_runs(current, previous)


class VulnerabilitiesFragment(View):
    """CVE / EOL 'protect yourself' panel from collected enrichment evidence."""

    methods: ClassVar[list[str]] = ["GET"]

    def dispatch_request(self) -> str:
        args = RequestArgs()
        query = VulnQuery(
            args.text("q"), args.text("severity"), args.text("source"), args.page()
        )
        with ServiceLookup().read_session() as session:
            return render_template(
                "partials/_vulnerabilities.html",
                vulns=VulnerabilitiesPanel(session).vulnerabilities(query),
                per_page_options=PER_PAGE_OPTIONS,
            )


class SysintFragment(LatestRunFragment):
    TEMPLATE = "partials/_sysint.html"
    KEY = "sysint"

    def build(self, session: Session, run_id: str) -> Any:
        return IntegrityPosture(session).for_run(run_id)


class ResourcesFragment(View):
    """System resources: memory/swap/CPU/load/uptime/tasks, the per-filesystem
    disk tree and the trend-chart canvases."""

    methods: ClassVar[list[str]] = ["GET"]

    def dispatch_request(self) -> str:
        with ServiceLookup().read_session() as session:
            latest = RunQueries(session).latest_run()
            resources = ResourceQueries(session)
            disks = resources.disk_usage(latest.run_id) if latest else []
            return render_template(
                "partials/_resources.html",
                resources=resources.host_resources(latest.run_id) if latest else None,
                disks_primary=DiskOrder().primary(disks),
                mounts=MountTree().nodes(disks),
            )


class NetworkFlowsFragment(LatestRunFragment):
    TEMPLATE = "partials/_network_flows.html"
    KEY = "flows"

    def build(self, session: Session, run_id: str) -> Any:
        args = RequestArgs()
        query = FlowQuery(args.row_filter(), args.page())
        return FlowsPanel(session, run_id).flows(query)


class ListeningPortsFragment(LatestRunFragment):
    TEMPLATE = "partials/_listening_ports.html"
    KEY = "ports"

    def build(self, session: Session, run_id: str) -> Any:
        args = RequestArgs()
        query = PortQuery(args.row_filter(), args.text("scope_filter"), args.page())
        return PortsPanel(session, run_id).ports(query)


class DnsQueriesFragment(LatestRunFragment):
    TEMPLATE = "partials/_dns_queries.html"
    KEY = "dns"

    def build(self, session: Session, run_id: str) -> Any:
        args = RequestArgs()
        query = DnsQuery(args.row_filter(), args.text("level"), args.page())
        return DnsPanel(session, run_id).queries(query)


class LogSummaryFragment(LatestRunFragment):
    TEMPLATE = "partials/_log_summary.html"
    KEY = "summary"

    def build(self, session: Session, run_id: str) -> Any:
        args = RequestArgs()
        filters = LogFilter(source=args.text("source"), search=args.text("q"))
        query = LogAggregateQuery(filters, args.text("group_by", "unit"), args.page())
        return LogsPanel(session, run_id).aggregates(query)


class LogsFragment(LatestRunFragment):
    TEMPLATE = "partials/_logs.html"
    KEY = "logs"

    def build(self, session: Session, run_id: str) -> Any:
        args = RequestArgs()
        filters = LogFilter(args.text("source"), args.text("level"), args.text("q"))
        return LogsPanel(session, run_id).entries(LogQuery(filters, args.page()))


class NetworkTopologyFragment(LatestRunFragment):
    TEMPLATE = "partials/_network_topology.html"
    KEY = "topo"

    def build(self, session: Session, run_id: str) -> Any:
        return NetworkPanels(session, run_id).topology(RequestArgs().row_filter())


class NetworkExposureFragment(LatestRunFragment):
    TEMPLATE = "partials/_network_exposure.html"
    KEY = "expo"

    def build(self, session: Session, run_id: str) -> Any:
        return NetworkPanels(session, run_id).exposure(RequestArgs().row_filter())


class PersistenceFragment(LatestRunFragment):
    TEMPLATE = "partials/_persistence.html"
    KEY = "data"

    def build(self, session: Session, run_id: str) -> Any:
        args = RequestArgs()
        pages = PersistencePages(
            ssh=args.page("ssh_page"),
            hosts=args.page("hosts_page"),
            priv=args.page("priv_page"),
        )
        return PersistencePanel(session, run_id).tampering(args.row_filter(), pages)


class FileScanFragment(LatestRunFragment):
    TEMPLATE = "partials/_file_scan.html"
    KEY = "data"

    def build(self, session: Session, run_id: str) -> Any:
        return YaraPanels(session).file_scan(run_id, RequestArgs().row_filter())


class ErrorsFragment(LatestRunFragment):
    TEMPLATE = "partials/_errors.html"
    KEY = "errors"
    EMPTY: ClassVar[Any] = []

    def build(self, session: Session, run_id: str) -> Any:
        return RunQueries(session).collector_errors(run_id)


class AuthEventsFragment(View):
    methods: ClassVar[list[str]] = ["GET"]

    def dispatch_request(self) -> str:
        args = RequestArgs()
        query = AuthQuery(
            args.row_filter(),
            args.text("subsystem"),
            args.text("sort", "count"),
            args.page(),
        )
        with ServiceLookup().read_session() as session:
            return render_template(
                "partials/_auth_events.html",
                events=AuthEventsPanel(session).aggregated(query),
                per_page_options=PER_PAGE_OPTIONS,
            )


class FindingsFragment(View):
    methods: ClassVar[list[str]] = ["GET"]
    FILTER_ARGS = ("verdict", "collector", "category", "q")

    def dispatch_request(self) -> str:
        args = RequestArgs()
        status = FindingStatus.parse(args.text("status", FindingStatus.ACTIVE))
        values = [args.text(name) for name in self.FILTER_ARGS]
        query = FindingsQuery(
            FindingFilter(*values, status),
            args.text("sort", "severity"),
            args.text("order", "desc"),
            args.page(),
        )
        with ServiceLookup().read_session() as session:
            return self._render(session, query)

    def _render(self, session: Session, query: FindingsQuery) -> str:
        found = FindingsPanel(session).findings(query)
        options = FindingOptions(session)
        return render_template(
            "partials/_findings.html",
            findings=found["items"],
            total=found["total"],
            page=found["page"],
            per_page=found["per_page"],
            total_pages=found["total_pages"],
            **self._echoed(query),
            collector_options=options.collectors(),
            category_options=options.categories(),
            per_page_options=PER_PAGE_OPTIONS,
        )

    def _echoed(self, query: FindingsQuery) -> dict[str, str]:
        filters = query.filters
        return {
            "verdict_filter": filters.verdict,
            "collector_filter": filters.collector,
            "category_filter": filters.category,
            "status_filter": filters.status.value,
            "q": filters.search,
            "sort": query.sort,
            "order": query.order,
        }


class RowCountsFragment(View):
    methods: ClassVar[list[str]] = ["GET"]

    def dispatch_request(self) -> str:
        with ServiceLookup().read_session() as session:
            counts = RowCountsView(session).for_latest()
            return render_template("partials/_row_counts.html", row_counts=counts)


class RunsFragment(View):
    methods: ClassVar[list[str]] = ["GET"]

    def dispatch_request(self) -> str:
        with ServiceLookup().read_session() as session:
            runs = RunQueries(session).recent_runs()
            return render_template("partials/_runs.html", recent_runs=runs)


class FragmentRoutes:
    """The ``fragments`` blueprint: (path, endpoint, view) per panel."""

    ROUTES = (
        ("/", "index", IndexView),
        ("/fragments/triage", "fragment_triage", TriageFragment),
        ("/fragments/header-meta", "fragment_header_meta", HeaderMetaFragment),
        ("/fragments/overview", "fragment_overview", OverviewFragment),
        ("/fragments/risk", "fragment_risk", RiskFragment),
        ("/fragments/incident", "fragment_incident", IncidentFragment),
        ("/fragments/verdicts", "fragment_verdicts", VerdictsFragment),
        ("/fragments/posture", "fragment_posture", PostureFragment),
        ("/fragments/collection", "fragment_collection", CollectionFragment),
        ("/fragments/network", "fragment_network", NetworkFragment),
        (
            "/fragments/vulnerabilities",
            "fragment_vulnerabilities",
            VulnerabilitiesFragment,
        ),
        ("/fragments/sysint", "fragment_sysint", SysintFragment),
        ("/fragments/resources", "fragment_resources", ResourcesFragment),
        ("/fragments/network-flows", "fragment_network_flows", NetworkFlowsFragment),
        (
            "/fragments/listening-ports",
            "fragment_listening_ports",
            ListeningPortsFragment,
        ),
        ("/fragments/dns-queries", "fragment_dns_queries", DnsQueriesFragment),
        ("/fragments/log-summary", "fragment_log_summary", LogSummaryFragment),
        ("/fragments/logs", "fragment_logs", LogsFragment),
        (
            "/fragments/network-topology",
            "fragment_network_topology",
            NetworkTopologyFragment,
        ),
        (
            "/fragments/network-exposure",
            "fragment_network_exposure",
            NetworkExposureFragment,
        ),
        ("/fragments/persistence", "fragment_persistence", PersistenceFragment),
        ("/fragments/auth-events", "fragment_auth_events", AuthEventsFragment),
        ("/fragments/errors", "fragment_errors", ErrorsFragment),
        ("/fragments/findings", "fragment_findings", FindingsFragment),
        ("/fragments/file-scan", "fragment_file_scan", FileScanFragment),
        ("/fragments/row-counts", "fragment_row_counts", RowCountsFragment),
        ("/fragments/runs", "fragment_runs", RunsFragment),
    )

    def blueprint(self) -> Blueprint:
        blueprint = Blueprint("fragments", __name__)
        for path, endpoint, view in self.ROUTES:
            blueprint.add_url_rule(path, view_func=view.as_view(endpoint))
        return blueprint
