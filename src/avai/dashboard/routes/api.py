"""JSON endpoints for the charts and the browser notifications."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import ClassVar

from flask import Blueprint, Response, jsonify, request

from ..queries import ResourceQueries, VerdictQueries
from . import DashboardServices, ServiceView


class VerdictChart(ServiceView):
    methods: ClassVar[list[str]] = ["GET"]

    def dispatch_request(self) -> Response:
        with self._services.read_session() as session:
            return jsonify(VerdictQueries(session).verdict_timeseries())


class ResourceChart(ServiceView):
    """Memory / CPU / swap percentage series for the resource trend charts
    (latest N runs)."""

    methods: ClassVar[list[str]] = ["GET"]

    def dispatch_request(self) -> Response:
        with self._services.read_session() as session:
            return jsonify(ResourceQueries(session).resource_trend())


class NewAlerts(ServiceView):
    """Malicious/suspicious judgements created after ``?since`` (the client's
    last-seen timestamp, kept in localStorage). ``now`` lets the client
    advance its cursor even when nothing is new, so a gap never re-alerts."""

    methods: ClassVar[list[str]] = ["GET"]

    def dispatch_request(self) -> Response:
        since = request.args.get("since", "")
        with self._services.read_session() as session:
            items = VerdictQueries(session).new_alerts(since or None)
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return jsonify({"since": since, "items": items, "now": now})


class ApiRoutes:
    ROUTES = (
        ("/api/chart/verdicts", "api_chart_verdicts", VerdictChart),
        ("/api/chart/resources", "api_chart_resources", ResourceChart),
        ("/api/notifications/new", "api_notifications_new", NewAlerts),
    )

    def __init__(self, services: DashboardServices) -> None:
        self._services = services

    def blueprint(self) -> Blueprint:
        blueprint = Blueprint("api", __name__)
        for path, endpoint, view in self.ROUTES:
            blueprint.add_url_rule(
                path, view_func=view.as_view(endpoint, self._services)
            )
        return blueprint
