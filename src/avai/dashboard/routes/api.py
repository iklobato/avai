"""JSON endpoints for the charts and the browser notifications."""

from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from ..queries import (
    new_alerts,
    resource_trend,
    verdict_timeseries,
)
from . import read_session

bp = Blueprint("api", __name__)


@bp.route("/api/chart/verdicts")
def api_chart_verdicts():
    with read_session() as s:
        return jsonify(verdict_timeseries(s, hours=12))


@bp.route("/api/chart/resources")
def api_chart_resources():
    """Memory / CPU / swap percentage time-series for the resource trend
    charts (latest N runs)."""
    with read_session() as s:
        return jsonify(resource_trend(s))


@bp.route("/api/notifications/new")
def api_notifications_new():
    """Return malicious/suspicious judgements created after ``?since``.
    The client supplies its last-seen timestamp (persisted in
    localStorage). The response also includes ``now`` so the client can
    advance its cursor even when there are no new items, avoiding
    re-alerting on the same gap if the timestamp ever changed."""
    since = request.args.get("since", "")
    with read_session() as s:
        items = new_alerts(s, since=since or None)
    return jsonify(
        {
            "since": since,
            "items": items,
            "now": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
    )
