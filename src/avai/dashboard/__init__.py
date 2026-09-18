"""avai.dashboard: package facade.

Re-exports the public surface (the app factory, query functions, CLI) so
callers and tests import from one place.
"""

from __future__ import annotations

from avai.host_monitor import Base  # re-export for callers

from .app import (
    _PKG_DIR,
    create_app,
)
from .config import (
    DEFAULT_DB_PATH,
    DashboardConfig,
)
from .control import (
    ControlStore,
    monitor_alive,
    read_control_state,
)
from .filters import (
    _LIST_ITEM_RE,
    _MD_TAGS,
    _datetime_fmt,
    _ensure_list_blank_lines,
    _flag_emoji,
    _human_bytes,
    _pretty_json,
    _relative_time,
    render_markdown,
)
from .queries import (
    AUTH_SUBSYSTEM_OPTIONS,
    COLLECTOR_MODELS,
    DEFAULT_PER_PAGE,
    DISPLAY_FIELDS,
    PER_PAGE_OPTIONS,
    SEVERITY_ORDER,
    VERDICTS,
    auth_events_aggregated,
    category_options,
    collector_errors,
    collector_options,
    cost_since,
    disk_usage,
    dns_queries,
    findings,
    host_resources,
    judged_since,
    latest_narrative,
    latest_risk,
    latest_run,
    listening_ports,
    network_flows,
    new_alerts,
    persistence_tampering,
    recent_runs,
    resource_trend,
    risk_trend,
    row_counts,
    runs_total,
    system_integrity,
    verdict_counts,
    verdict_timeseries,
    vulnerabilities,
)
from .queries.auth_events import (
    _AUTH_AGG_WINDOW_HOURS,
    _AUTH_SUBSYSTEM_LABELS,
    _AUTH_VERDICT_SEV,
)
from .queries.collection import (
    _STREAMING_COLLECTORS,
)
from .queries.common import (
    _FLOW_SEV,
    _HIDDEN_SOURCE_FIELDS,
    _SCHEMA_TTL,
    _cache_key,
    _columns_cache,
    _existing_columns,
    _existing_tables,
    _parse_json_list,
    _parse_json_obj,
    _port_sort_key,
    _row_and_artifact,
    _tables_cache,
)
from .queries.dns import (
    _dns_resolution_level,
)
from .queries.findings import (
    _SEVERITY_CASE,
    _SORT_FIELDS,
)
from .queries.ip_enrichment import (
    _attach_ip_enrichment,
    _geo_from_details,
    _geo_richness,
    _host_from_details,
)
from .queries.ports import (
    _FAMILY_LABEL,
    _PROTO_BY_SOCK,
    _SCOPE_SEV,
    _addr_scope,
    _cmdline_str,
)
from .queries.vulnerabilities import (
    _VULN_SOURCES,
)
from .routes.fragments import (
    _int_arg,
    _prior_run,
    _sparkline_points,
)
from .serve import (
    _build_parser,
    _ensure_db_exists,
    _open_browser,
    _serve,
    main,
)

__all__ = [
    "AUTH_SUBSYSTEM_OPTIONS",
    "Base",
    "COLLECTOR_MODELS",
    "ControlStore",
    "DEFAULT_DB_PATH",
    "DEFAULT_PER_PAGE",
    "DISPLAY_FIELDS",
    "DashboardConfig",
    "PER_PAGE_OPTIONS",
    "SEVERITY_ORDER",
    "VERDICTS",
    "_AUTH_AGG_WINDOW_HOURS",
    "_AUTH_SUBSYSTEM_LABELS",
    "_AUTH_VERDICT_SEV",
    "_FAMILY_LABEL",
    "_FLOW_SEV",
    "_HIDDEN_SOURCE_FIELDS",
    "_LIST_ITEM_RE",
    "_MD_TAGS",
    "_PKG_DIR",
    "_PROTO_BY_SOCK",
    "_SCHEMA_TTL",
    "_SCOPE_SEV",
    "_SEVERITY_CASE",
    "_SORT_FIELDS",
    "_STREAMING_COLLECTORS",
    "_VULN_SOURCES",
    "_addr_scope",
    "_attach_ip_enrichment",
    "_build_parser",
    "_cache_key",
    "_cmdline_str",
    "_columns_cache",
    "_datetime_fmt",
    "_dns_resolution_level",
    "_ensure_db_exists",
    "_ensure_list_blank_lines",
    "_existing_columns",
    "_existing_tables",
    "_flag_emoji",
    "_geo_from_details",
    "_geo_richness",
    "_host_from_details",
    "_human_bytes",
    "_int_arg",
    "_open_browser",
    "_parse_json_list",
    "_parse_json_obj",
    "_port_sort_key",
    "_pretty_json",
    "_prior_run",
    "_relative_time",
    "_row_and_artifact",
    "_serve",
    "_sparkline_points",
    "_tables_cache",
    "auth_events_aggregated",
    "category_options",
    "collector_errors",
    "collector_options",
    "cost_since",
    "create_app",
    "disk_usage",
    "dns_queries",
    "findings",
    "host_resources",
    "judged_since",
    "latest_narrative",
    "latest_risk",
    "latest_run",
    "listening_ports",
    "main",
    "monitor_alive",
    "network_flows",
    "new_alerts",
    "persistence_tampering",
    "read_control_state",
    "recent_runs",
    "render_markdown",
    "resource_trend",
    "risk_trend",
    "row_counts",
    "runs_total",
    "system_integrity",
    "verdict_counts",
    "verdict_timeseries",
    "vulnerabilities",
]
