"""avai — macOS / Linux host security telemetry collector with an LLM
threat judge and a single-page web dashboard.

Public entry points:

    avai monitor [...]      run the host monitor (host_monitor.main.MonitorApp)
    avai dashboard [...]    run the read-only Flask dashboard
                            (dashboard.serve.DashboardCli)

Or programmatically:

    from avai.host_monitor import HostFactory, Sink, Runner
    from avai.dashboard import DashboardApp, DashboardConfig
    dashboard_app = DashboardApp(DashboardConfig(db_path=...)).build()
"""

__version__ = "0.9.2"
