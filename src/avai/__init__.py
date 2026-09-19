"""avai — macOS / Linux host security telemetry collector with an LLM
threat judge and a single-page web dashboard.

Public entry points:

    avai monitor [...]      run the host monitor (host_monitor.main)
    avai dashboard [...]    run the read-only Flask dashboard
                            (dashboard.main)

Or programmatically:

    from avai.host_monitor import HostFactory, Sink, Runner
    from avai.dashboard import DashboardConfig, create_app
    dashboard_app = create_app(DashboardConfig(db_path=...))
"""

__version__ = "0.7.3"
