"""avai.dashboard: package facade.

Re-exports only what code outside the package imports from here: the CLI
entry point and what the desktop app needs to serve the dashboard in a
thread. Everything else is imported from its own submodule.
"""

from __future__ import annotations

from .app import DashboardApp
from .config import DashboardConfig
from .serve import DashboardCli, DashboardSchema

__all__ = [
    "DashboardApp",
    "DashboardCli",
    "DashboardConfig",
    "DashboardSchema",
]
