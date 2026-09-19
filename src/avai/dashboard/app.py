"""Flask application factory: security headers, template filters, routes."""

from __future__ import annotations

from pathlib import Path

from flask import Flask

from .config import DashboardConfig
from .control import ControlStore
from .db import read_only_engine, writable_engine
from .filters import register_filters
from .routes import DashboardServices, api, control, fragments

_PKG_DIR = Path(__file__).resolve().parent.parent


# Content-Security-Policy: the dashboard ships its own vendored JS/CSS and uses
# a few inline <script>/<style> blocks plus Tailwind's Play build (which compiles
# via eval), so script/style need 'unsafe-inline'/'unsafe-eval'. frame-ancestors
# 'none' (with X-Frame-Options) blocks clickjacking of the control buttons.
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


def _security_headers(response):
    """Add baseline security headers to every response and drop the server
    banner. The dashboard is loopback-only by default, but these are cheap
    defense-in-depth (clickjacking, MIME sniffing, referrer leakage)."""
    response.headers.setdefault("Content-Security-Policy", _CSP)
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers["Server"] = "avai"
    return response


def create_app(config: DashboardConfig) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(_PKG_DIR / "templates"),
        static_folder=str(_PKG_DIR / "static"),
    )
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.jinja_env.auto_reload = True
    app.after_request(_security_headers)
    register_filters(app)
    DashboardServices(
        config,
        read_only_engine(config.db_path, config.query_log_path),
        ControlStore(writable_engine(config.db_path)),
    ).install(app)
    for blueprint in (fragments.bp, api.bp, control.bp):
        app.register_blueprint(blueprint)
    return app
