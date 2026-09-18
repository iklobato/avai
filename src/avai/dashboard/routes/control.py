"""The cooperative control plane: POST routes write the control_state row
the monitor obeys, and operator feedback on findings. Guarded by a shared
secret token (fail closed when unset)."""

from __future__ import annotations

import hmac
from functools import wraps

from flask import Blueprint, abort, render_template, request

from avai.host_monitor import FeedbackLabel

from ..control import monitor_alive, read_control_state
from ..queries import COLLECTOR_MODELS
from . import read_session, services

bp = Blueprint("control", __name__)


_MAINTENANCE_ACTIONS = {"prune", "clear", "rejudge", "renarrate", "reset_baseline"}


def require_control_token(fn):
    """Gate a control action behind the configured token. Fails closed: with
    no token, control is disabled entirely (403). The token is read from the
    ``X-Avai-Token`` header; a custom header can't be set by a cross-site
    form, so it doubles as the CSRF defence. Bypassed in open mode (see
    ``DashboardConfig.control_open``)."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        config = services().config
        if config.control_open:
            return fn(*args, **kwargs)
        supplied = request.headers.get("X-Avai-Token", "")
        token = config.control_token
        if not token or not hmac.compare_digest(token, supplied):
            abort(403)
        return fn(*args, **kwargs)

    return wrapper


def _control_panel():
    config = services().config
    with read_session() as s:
        state = read_control_state(s)
    return render_template(
        "partials/_control.html",
        ctrl=state,
        alive=monitor_alive(state),
        collectors=sorted(COLLECTOR_MODELS),
        control_enabled=config.control_enabled,
        control_open=config.control_open,
    )


@bp.route("/fragments/control")
def fragment_control():
    return _control_panel()


@bp.route("/control/pause", methods=["POST"])
@require_control_token
def control_pause():
    services().control.set_paused(True)
    return _control_panel()


@bp.route("/control/resume", methods=["POST"])
@require_control_token
def control_resume():
    services().control.set_paused(False)
    return _control_panel()


@bp.route("/control/scan-now", methods=["POST"])
@require_control_token
def control_scan_now():
    services().control.bump_scan_now()
    return _control_panel()


@bp.route("/control/collector/<name>/<state>", methods=["POST"])
@require_control_token
def control_collector(name, state):
    if name not in COLLECTOR_MODELS or state not in ("on", "off"):
        abort(400)
    services().control.set_collector(name, enabled=(state == "on"))
    return _control_panel()


@bp.route("/control/settings", methods=["POST"])
@require_control_token
def control_settings():
    def _int(field):
        v = request.form.get(field, "").strip()
        return int(v) if v.isdigit() else None

    def _bool(field):
        v = request.form.get(field)
        return None if v is None else v in ("1", "true", "on", "yes")

    services().control.set_settings(
        interval=_int("interval"), judge=_bool("judge"), enrich=_bool("enrich")
    )
    return _control_panel()


@bp.route("/control/maintenance/<action>", methods=["POST"])
@require_control_token
def control_maintenance(action):
    if action not in _MAINTENANCE_ACTIONS:
        abort(400)
    services().control.queue_command(action)
    return _control_panel()


_FEEDBACK_LABELS = {label.value for label in FeedbackLabel}


@bp.route("/feedback/<collector>/<content_hash>/<label>", methods=["POST"])
@require_control_token
def feedback_record(collector, content_hash, label):
    """Record an operator correction on a finding. The monitor applies it to
    the verdict and feeds it back to the judge next cycle, so the on-screen
    verdict updates on the following refresh (not instantly)."""
    if collector not in COLLECTOR_MODELS or label not in _FEEDBACK_LABELS:
        abort(400)
    services().control.record_feedback(
        content_hash=content_hash,
        collector=collector,
        label=label,
        note=(request.form.get("note", "").strip() or None),
        artifact=(request.form.get("artifact", "").strip() or None),
    )
    return (
        '<span class="text-emerald-400 text-[10px] uppercase tracking-wider">'
        "✓ recorded — applies next cycle</span>"
    )
