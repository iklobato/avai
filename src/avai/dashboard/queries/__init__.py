"""Read-only DB query layer, one module per dashboard panel. Every function
takes a Session; none touches Flask."""

from .auth_events import AUTH_SUBSYSTEM_OPTIONS, auth_events_aggregated
from .collection import (
    collector_errors,
    cost_since,
    judged_since,
    latest_narrative,
    latest_risk,
    latest_run,
    new_alerts,
    recent_runs,
    risk_trend,
    row_counts,
    runs_total,
    verdict_counts,
    verdict_timeseries,
)
from .common import (
    COLLECTOR_MODELS,
    DEFAULT_PER_PAGE,
    DISPLAY_FIELDS,
    PER_PAGE_OPTIONS,
    VERDICTS,
    Page,
)
from .dns import dns_queries
from .exposure import network_exposure, network_topology
from .findings import category_options, collector_options, findings
from .flows import network_flows
from .logs import LOG_LEVELS, log_aggregates, log_entries
from .ports import listening_ports
from .posture import (
    PersistencePages,
    file_scan,
    persistence_tampering,
    system_integrity,
    yara_coverage,
    yara_status,
)
from .resources import (
    disk_usage,
    host_resources,
    mount_tree,
    primary_filesystems,
    resource_trend,
)
from .vulnerabilities import SEVERITY_ORDER, vulnerabilities

__all__ = [
    "AUTH_SUBSYSTEM_OPTIONS",
    "COLLECTOR_MODELS",
    "DEFAULT_PER_PAGE",
    "DISPLAY_FIELDS",
    "LOG_LEVELS",
    "PER_PAGE_OPTIONS",
    "SEVERITY_ORDER",
    "VERDICTS",
    "Page",
    "PersistencePages",
    "auth_events_aggregated",
    "category_options",
    "collector_errors",
    "collector_options",
    "cost_since",
    "disk_usage",
    "dns_queries",
    "file_scan",
    "findings",
    "host_resources",
    "judged_since",
    "latest_narrative",
    "latest_risk",
    "latest_run",
    "listening_ports",
    "log_aggregates",
    "log_entries",
    "mount_tree",
    "network_exposure",
    "network_flows",
    "network_topology",
    "new_alerts",
    "persistence_tampering",
    "primary_filesystems",
    "recent_runs",
    "resource_trend",
    "risk_trend",
    "row_counts",
    "runs_total",
    "system_integrity",
    "verdict_counts",
    "verdict_timeseries",
    "vulnerabilities",
    "yara_coverage",
    "yara_status",
]
