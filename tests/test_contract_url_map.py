"""Pins every dashboard URL (path, endpoint, methods): templates hardcode the paths."""

from __future__ import annotations

from pathlib import Path

from avai.dashboard.app import DashboardApp
from avai.dashboard.config import DashboardConfig
from avai.dashboard.serve import DashboardSchema

IGNORED_METHODS = frozenset({"HEAD", "OPTIONS"})

EXPECTED_RULES = frozenset(
    {
        ("/", "board.board_index", ("GET",)),
        ("/classic", "fragments.index", ("GET",)),
        ("/board/alerts", "board.board_alerts", ("GET",)),
        ("/board/changes", "board.board_changes", ("GET",)),
        ("/board/collection", "board.board_collection", ("GET",)),
        ("/board/exec-feed", "board.board_exec_feed", ("GET",)),
        (
            "/board/feedback/<collector>/<content_hash>/<label>",
            "board.board_feedback",
            ("POST",),
        ),
        ("/board/findings", "board.board_findings", ("GET",)),
        ("/board/host", "board.board_host", ("GET",)),
        ("/board/incident", "board.board_incident", ("GET",)),
        (
            "/board/inspect/<collector>/<content_hash>",
            "board.board_inspect",
            ("GET",),
        ),
        ("/board/inspect-vuln", "board.board_inspect_vuln", ("GET",)),
        ("/board/network", "board.board_network", ("GET",)),
        ("/board/ports", "board.board_ports", ("GET",)),
        ("/board/rates", "board.board_rates", ("GET",)),
        ("/board/setup", "board.board_setup", ("GET",)),
        ("/board/threat-stats", "board.board_threat_stats", ("GET",)),
        ("/board/topbar", "board.board_topbar", ("GET",)),
        ("/api/chart/resources", "api.api_chart_resources", ("GET",)),
        ("/api/chart/verdicts", "api.api_chart_verdicts", ("GET",)),
        ("/api/notifications/new", "api.api_notifications_new", ("GET",)),
        ("/control/collector/<name>/<state>", "control.control_collector", ("POST",)),
        ("/control/maintenance/<action>", "control.control_maintenance", ("POST",)),
        ("/control/pause", "control.control_pause", ("POST",)),
        ("/control/resume", "control.control_resume", ("POST",)),
        ("/control/scan-now", "control.control_scan_now", ("POST",)),
        ("/control/settings", "control.control_settings", ("POST",)),
        (
            "/feedback/<collector>/<content_hash>/<label>",
            "control.feedback_record",
            ("POST",),
        ),
        ("/fragments/auth-events", "fragments.fragment_auth_events", ("GET",)),
        ("/fragments/collection", "fragments.fragment_collection", ("GET",)),
        ("/fragments/control", "control.fragment_control", ("GET",)),
        ("/fragments/dns-queries", "fragments.fragment_dns_queries", ("GET",)),
        ("/fragments/errors", "fragments.fragment_errors", ("GET",)),
        ("/fragments/file-scan", "fragments.fragment_file_scan", ("GET",)),
        ("/fragments/findings", "fragments.fragment_findings", ("GET",)),
        ("/fragments/header-meta", "fragments.fragment_header_meta", ("GET",)),
        ("/fragments/incident", "fragments.fragment_incident", ("GET",)),
        ("/fragments/listening-ports", "fragments.fragment_listening_ports", ("GET",)),
        ("/fragments/log-summary", "fragments.fragment_log_summary", ("GET",)),
        ("/fragments/logs", "fragments.fragment_logs", ("GET",)),
        ("/fragments/network", "fragments.fragment_network", ("GET",)),
        (
            "/fragments/network-exposure",
            "fragments.fragment_network_exposure",
            ("GET",),
        ),
        ("/fragments/network-flows", "fragments.fragment_network_flows", ("GET",)),
        (
            "/fragments/network-topology",
            "fragments.fragment_network_topology",
            ("GET",),
        ),
        ("/fragments/overview", "fragments.fragment_overview", ("GET",)),
        ("/fragments/persistence", "fragments.fragment_persistence", ("GET",)),
        ("/fragments/posture", "fragments.fragment_posture", ("GET",)),
        ("/fragments/resources", "fragments.fragment_resources", ("GET",)),
        ("/fragments/risk", "fragments.fragment_risk", ("GET",)),
        ("/fragments/row-counts", "fragments.fragment_row_counts", ("GET",)),
        ("/fragments/runs", "fragments.fragment_runs", ("GET",)),
        ("/fragments/sysint", "fragments.fragment_sysint", ("GET",)),
        ("/fragments/triage", "fragments.fragment_triage", ("GET",)),
        ("/fragments/verdicts", "fragments.fragment_verdicts", ("GET",)),
        ("/fragments/vulnerabilities", "fragments.fragment_vulnerabilities", ("GET",)),
        ("/static/<path:filename>", "static", ("GET",)),
    }
)


def test_url_map_paths_endpoints_and_methods_are_unchanged(tmp_path: Path) -> None:
    db_path = str(tmp_path / "contract.db")
    DashboardSchema().ensure(db_path)
    app = DashboardApp(DashboardConfig(db_path=db_path)).build()

    actual = {
        (rule.rule, rule.endpoint, tuple(sorted(rule.methods - IGNORED_METHODS)))
        for rule in app.url_map.iter_rules()
    }

    assert actual == EXPECTED_RULES
