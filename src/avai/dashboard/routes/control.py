"""The cooperative control plane: POST routes write the control_state row
the monitor obeys, and operator feedback on findings. Guarded by a shared
secret token (fail closed when unset)."""

from __future__ import annotations

import hmac
from enum import StrEnum
from http import HTTPStatus
from typing import ClassVar

from flask import Blueprint, abort, render_template, request

from avai.host_monitor import FeedbackLabel
from avai.host_monitor.enums import MaintenanceCommand

from ..control import (
    ControlReader,
    ControlStore,
    Feedback,
    MonitorLiveness,
    SettingsChange,
)
from ..queries import CollectorTables
from . import DashboardServices, ServiceView

TRUTHY_FORM_VALUES = ("1", "true", "on", "yes")


class TokenGate:
    """Gate a control action behind the configured token. Fails closed: with
    no token, control is disabled entirely (403). The token comes from the
    ``X-Avai-Token`` header; a cross-site form can't set a custom header, so
    it doubles as the CSRF defence. Open mode (see
    ``DashboardConfig.control_open``) skips the check."""

    def __init__(self, services: DashboardServices) -> None:
        self._services = services

    def check(self) -> None:
        config = self._services.config
        if config.control_open:
            return
        supplied = request.headers.get("X-Avai-Token", "")
        token = config.control_token
        if not token or not hmac.compare_digest(token, supplied):
            abort(HTTPStatus.FORBIDDEN)


class ControlPanel:
    def __init__(self, services: DashboardServices) -> None:
        self._services = services

    def render(self) -> str:
        config = self._services.config
        with self._services.read_session() as session:
            state = ControlReader().read(session)
        return render_template(
            "partials/_control.html",
            ctrl=state,
            alive=MonitorLiveness(self._services.clock).alive(state),
            collectors=sorted(CollectorTables().models()),
            control_enabled=config.control_enabled,
            control_open=config.control_open,
        )


class GuardedAction(ServiceView):
    """A token-guarded POST that changes the control row, then re-renders the
    control panel."""

    methods: ClassVar[list[str]] = ["POST"]

    def store(self) -> ControlStore:
        return self._services.control


class ControlFragment(ServiceView):
    methods: ClassVar[list[str]] = ["GET"]

    def dispatch_request(self) -> str:
        return ControlPanel(self._services).render()


class PauseAction(GuardedAction):
    def dispatch_request(self) -> str:
        TokenGate(self._services).check()
        self.store().pause()
        return ControlPanel(self._services).render()


class ResumeAction(GuardedAction):
    def dispatch_request(self) -> str:
        TokenGate(self._services).check()
        self.store().resume()
        return ControlPanel(self._services).render()


class ScanNowAction(GuardedAction):
    def dispatch_request(self) -> str:
        TokenGate(self._services).check()
        self.store().bump_scan_now()
        return ControlPanel(self._services).render()


class CollectorSwitch(StrEnum):
    ON = "on"
    OFF = "off"


class CollectorAction(GuardedAction):
    def dispatch_request(self, name: str, state: str) -> str:
        TokenGate(self._services).check()
        if CollectorTables().model(name) is None or state not in tuple(CollectorSwitch):
            abort(HTTPStatus.BAD_REQUEST)
        store = self.store()
        switches = {
            CollectorSwitch.ON: store.enable_collector,
            CollectorSwitch.OFF: store.disable_collector,
        }
        switches[CollectorSwitch(state)](name)
        return ControlPanel(self._services).render()


class SettingsAction(GuardedAction):
    def dispatch_request(self) -> str:
        TokenGate(self._services).check()
        change = SettingsChange(
            interval=self._number("interval"),
            judge=self._flag("judge"),
            enrich=self._flag("enrich"),
            verify=self._flag("verify"),
            investigate=self._flag("investigate"),
        )
        self.store().set_settings(change)
        return ControlPanel(self._services).render()

    def _number(self, field: str) -> int | None:
        value = request.form.get(field, "").strip()
        return int(value) if value.isdigit() else None

    def _flag(self, field: str) -> bool | None:
        value = request.form.get(field)
        return None if value is None else value in TRUTHY_FORM_VALUES


class MaintenanceAction(GuardedAction):
    def dispatch_request(self, action: str) -> str:
        TokenGate(self._services).check()
        if action not in tuple(MaintenanceCommand):
            abort(HTTPStatus.BAD_REQUEST)
        self.store().queue_command(MaintenanceCommand(action))
        return ControlPanel(self._services).render()


class FeedbackAction(GuardedAction):
    """Record an operator correction on a finding. The monitor applies it to
    the verdict and feeds it back to the judge next cycle, so the on-screen
    verdict updates on the following refresh (not instantly)."""

    RECORDED = (
        '<span class="text-emerald-400 text-[10px] uppercase tracking-wider">'
        "✓ recorded — applies next cycle</span>"
    )

    def dispatch_request(self, collector: str, content_hash: str, label: str) -> str:
        TokenGate(self._services).check()
        if CollectorTables().model(collector) is None or label not in tuple(
            FeedbackLabel
        ):
            abort(HTTPStatus.BAD_REQUEST)
        note = request.form.get("note", "").strip() or None
        artifact = request.form.get("artifact", "").strip() or None
        self.store().record_feedback(
            Feedback(content_hash, collector, FeedbackLabel(label), note, artifact)
        )
        return self.RECORDED


class ControlRoutes:
    ROUTES = (
        ("/fragments/control", "fragment_control", ControlFragment),
        ("/control/pause", "control_pause", PauseAction),
        ("/control/resume", "control_resume", ResumeAction),
        ("/control/scan-now", "control_scan_now", ScanNowAction),
        ("/control/collector/<name>/<state>", "control_collector", CollectorAction),
        ("/control/settings", "control_settings", SettingsAction),
        ("/control/maintenance/<action>", "control_maintenance", MaintenanceAction),
        (
            "/feedback/<collector>/<content_hash>/<label>",
            "feedback_record",
            FeedbackAction,
        ),
    )

    def __init__(self, services: DashboardServices) -> None:
        self._services = services

    def blueprint(self) -> Blueprint:
        blueprint = Blueprint("control", __name__)
        for path, endpoint, view in self.ROUTES:
            blueprint.add_url_rule(
                path, view_func=view.as_view(endpoint, self._services)
            )
        return blueprint
