"""What one dashboard instance runs with, read once at startup."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

DEFAULT_DB_PATH = Path.home() / ".avai" / "avai.db"


class EnvToggle:
    """An on/off environment variable. Only an explicit "on" value turns it
    on, so ``AVAI_CONTROL_OPEN=0`` keeps control closed (fail closed)."""

    ON_VALUES = frozenset({"1", "true", "yes", "on"})

    def __init__(self, environ: Mapping[str, str]) -> None:
        self._environ = environ

    def is_on(self, name: str) -> bool:
        return self._environ.get(name, "").strip().lower() in self.ON_VALUES


@dataclass(frozen=True)
class DashboardConfig:
    db_path: str
    # Fail closed: with no token and no open mode, control is disabled (403).
    control_token: Optional[str] = None
    # The desktop app sets this: the dashboard is bound to loopback inside a
    # single-user webview the user owns, so the token (a CSRF defence for the
    # network ``avai dashboard``) is just friction.
    control_open: bool = False
    # Antivirus-style protection home at the top of the page (desktop app).
    app_mode: bool = False
    # Append every SQL statement to this file (debugging slow panels).
    query_log_path: Optional[str] = None

    @classmethod
    def from_env(
        cls, db_path: str, environ: Mapping[str, str] = os.environ
    ) -> DashboardConfig:
        toggle = EnvToggle(environ)
        return cls(
            db_path=db_path,
            control_token=environ.get("AVAI_CONTROL_TOKEN") or None,
            control_open=toggle.is_on("AVAI_CONTROL_OPEN"),
            app_mode=toggle.is_on("AVAI_APP_MODE"),
            query_log_path=environ.get("AVAI_QUERY_LOG") or None,
        )

    @property
    def control_enabled(self) -> bool:
        return bool(self.control_token) or self.control_open
