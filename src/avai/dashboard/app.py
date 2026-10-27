"""Flask application factory: security headers, template filters, routes."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, Response

from avai.host_monitor.runtime import Clock

from .config import DashboardConfig
from .control import ControlStore
from .db import DashboardEngines
from .filters import TemplateFilters
from .queries.auth_events import AuthCaches
from .routes import DashboardServices
from .routes.api import ApiRoutes
from .routes.control import ControlRoutes
from .routes.fragments import FragmentRoutes

PACKAGE_DIR = Path(__file__).resolve().parent.parent

# Content-Security-Policy: the dashboard ships its own vendored JS/CSS and uses
# a few inline <script>/<style> blocks plus Tailwind's Play build (which compiles
# via eval), so script/style need 'unsafe-inline'/'unsafe-eval'. frame-ancestors
# 'none' (with X-Frame-Options) blocks clickjacking of the control buttons.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


class SecurityHeaders:
    """Baseline security headers on every response, without the server
    banner. The dashboard is loopback-only by default; these are cheap
    defense-in-depth (clickjacking, MIME sniffing, referrer leakage)."""

    def apply(self, response: Response) -> Response:
        response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers["Server"] = "avai"
        return response


class DashboardApp:
    def __init__(self, config: DashboardConfig) -> None:
        self._config = config

    def build(self) -> Flask:
        app = Flask(
            __name__,
            template_folder=str(PACKAGE_DIR / "templates"),
            static_folder=str(PACKAGE_DIR / "static"),
        )
        app.config["TEMPLATES_AUTO_RELOAD"] = True
        app.jinja_env.auto_reload = True
        app.after_request(SecurityHeaders().apply)
        services = self._services()
        TemplateFilters(services.clock).register(app)
        routes = (
            FragmentRoutes(services),
            ApiRoutes(services),
            ControlRoutes(services),
        )
        for route_set in routes:
            app.register_blueprint(route_set.blueprint())
        return app

    def _services(self) -> DashboardServices:
        config, engines, clock = self._config, DashboardEngines(), Clock()
        return DashboardServices(
            config,
            engines.read_only(config.db_path, config.query_log_path),
            ControlStore(engines.writable(config.db_path), clock),
            clock,
            AuthCaches.create(clock),
        )
