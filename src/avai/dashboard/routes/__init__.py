"""HTTP routes, one Blueprint per surface: HTML fragments, the JSON api and
the token-guarded control plane. They reach the database only through the
services the app hands to each view."""

from __future__ import annotations

from dataclasses import dataclass

from flask.views import View
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from avai.host_monitor.runtime import Clock

from ..config import DashboardConfig
from ..control import ControlStore


@dataclass(frozen=True)
class DashboardServices:
    config: DashboardConfig
    read_engine: Engine
    control: ControlStore
    clock: Clock

    def read_session(self) -> Session:
        return Session(self.read_engine)


class ServiceView(View):
    """A view built with the app's services: ``as_view(endpoint, services)``
    passes them to the constructor."""

    def __init__(self, services: DashboardServices) -> None:
        self._services = services
