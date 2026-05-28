"""avai — macOS / Linux host security telemetry collector with an LLM
threat judge and a single-page web dashboard.

Public entry points:

    avai monitor [...]      run the host monitor (host_monitor.main)
    avai dashboard [...]    run the read-only Flask dashboard
                            (dashboard.main)

Or programmatically:

    from avai.host_monitor import build_snapshot_collectors, Sink, Runner
    from avai.dashboard import app as dashboard_app
"""

__version__ = "0.2.0"
