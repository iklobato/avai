# avai — multi-stage image
#
#   base       — Python deps shared by both services. Used directly by
#                neither; both final stages FROM base.
#   dashboard  — slim, non-root, no host-monitoring binaries. Read-only
#                Flask viewer over the SQLite database. Final image
#                ~200 MB.
#   monitor    — adds iw, systemd (for systemctl + journalctl),
#                dmsetup, bluez, dpkg so the Linux collectors can
#                actually run. Runs as root in the docker-compose
#                service. Final image ~350 MB.
#
# docker-compose.yml picks one per service via `build.target`.

ARG PYTHON_VERSION=3.11


# ---------------------------------------------------------------------------
# base — Python runtime + shared deps + app source
# ---------------------------------------------------------------------------

FROM python:${PYTHON_VERSION}-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# host_monitor.py imports psutil and sqlalchemy at module top; the
# litellm/anthropic imports are guarded by try/except. We install all
# four here so the same base image powers both services.
RUN pip install \
        flask==3.0.* \
        sqlalchemy==2.0.* \
        psutil==5.9.* \
        "litellm>=1.0" \
        "anthropic>=0.30"

COPY host_monitor.py dashboard.py host_monitor_prompts.toml ./
COPY templates ./templates


# ---------------------------------------------------------------------------
# dashboard — slim, non-root, read-only-friendly. No monitoring tools.
# ---------------------------------------------------------------------------

FROM base AS dashboard

RUN useradd --create-home --uid 1000 avai \
 && mkdir -p /data \
 && chown -R avai:avai /data
USER avai

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8765/api/notifications/new?since=2099-01-01', timeout=3).status==200 else 1)"

CMD ["python", "dashboard.py", \
     "--host", "0.0.0.0", "--port", "8765", \
     "--db", "/data/host_monitor.db"]


# ---------------------------------------------------------------------------
# monitor — adds the Linux userland the host-monitoring collectors call.
# ---------------------------------------------------------------------------

FROM base AS monitor

# Apt deps required by the Linux collector set:
#
#   iw           — LinuxWifiCollector parses `iw dev <iface> link`
#   systemd      — provides systemctl (LinuxSystemIntegrityCollector) and
#                  journalctl (LinuxAuthEventsCollector). Large dep.
#                  We do NOT run systemd itself; only its CLIs.
#   dbus         — pulled in by systemd; needed for systemctl to talk
#                  to the host's bus over the bind-mounted socket.
#   dmsetup      — LinuxSystemIntegrityCollector counts LUKS mappings
#   bluez       — bluetoothctl + the libs that read /var/lib/bluetooth
#   dpkg        — already in python:3.11-slim (debian-based) but listed
#                 explicitly so the intent is clear; dpkg-query is the
#                 binary LinuxInstalledAppsCollector calls.
#   util-linux  — present in base image; provides lsblk, mount, etc.
#                 (no install needed)
#   ca-certificates — for litellm/anthropic HTTPS calls
#
# /var/lib/apt/lists is the build cache; remove to keep the image small.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iw \
        systemd \
        dbus \
        dmsetup \
        bluez \
        dpkg \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Runs as root in compose — the host monitor needs CAP_SYS_PTRACE,
# CAP_DAC_READ_SEARCH and visibility into the host PID + network
# namespaces, none of which a non-root user inside the container
# would have.

# Healthcheck: the monitor writes to the bind-mounted DB; presence of
# the file means the first cycle completed (after which it gets
# updated continuously).
HEALTHCHECK --interval=60s --timeout=4s --start-period=30s --retries=3 \
  CMD test -f /data/host_monitor.db

CMD ["python", "host_monitor.py", \
     "--db", "/data/host_monitor.db", \
     "--interval", "300", \
     "--lookback-min", "6", \
     "--max-db-mb", "1024", \
     "--judge-max-per-collector", "60"]
