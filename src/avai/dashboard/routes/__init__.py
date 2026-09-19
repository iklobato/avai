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

_EXTENSION_KEY = "avai"


@dataclass(frozen=True)
class DashboardServices:
    config: DashboardConfig
    read_engine: Engine
    control: ControlStore

    def install(self, app: Flask) -> None:
        app.extensions[_EXTENSION_KEY] = self


def services() -> DashboardServices:
    return current_app.extensions[_EXTENSION_KEY]


def read_session() -> Session:
    return Session(services().read_engine)
