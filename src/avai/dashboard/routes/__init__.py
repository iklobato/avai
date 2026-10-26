"""HTTP routes, one Blueprint per surface: HTML fragments, the JSON api and
the token-guarded control plane. They reach the database only through the
services ``create_app`` installs on the app."""

from __future__ import annotations

from dataclasses import dataclass

from flask import Flask, current_app
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from ..config import DashboardConfig
from ..control import ControlStore

EXTENSION_KEY = "avai"


@dataclass(frozen=True)
class DashboardServices:
    config: DashboardConfig
    read_engine: Engine
    control: ControlStore

    def install(self, app: Flask) -> None:
        app.extensions[EXTENSION_KEY] = self


class ServiceLookup:
    """The services the running app installed, from inside a request."""

    def services(self) -> DashboardServices:
        return current_app.extensions[EXTENSION_KEY]

    def read_session(self) -> Session:
        return Session(self.services().read_engine)
