# avai dashboard image
#
# A slim read-only viewer for the SQLite database that host_monitor.py
# writes on the macOS host. The host monitor itself is NOT shipped as a
# runnable service in this image — its collectors require macOS-native
# tools (system_profiler, log stream, launchctl, TCC.db, native psutil
# process visibility) that don't exist or are unreachable from a Linux
# container running inside Docker Desktop's VM. The monitor must run
# natively on the host. See README.md for the recommended invocation.

ARG PYTHON_VERSION=3.11

FROM python:${PYTHON_VERSION}-slim AS base

# Predictable Python runtime: don't buffer stdout (so docker logs show
# things live), don't write .pyc files (saves a few MB at runtime).
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Runtime deps for the dashboard. host_monitor.py is imported (for its
# SQLAlchemy ORM models) so psutil and sqlalchemy need to be present,
# but litellm / anthropic are guarded by try/except at import time and
# aren't needed by the dashboard path.
RUN pip install \
        flask==3.0.* \
        sqlalchemy==2.0.* \
        psutil==5.9.*

# Source layout: only what the dashboard needs at runtime.
COPY host_monitor.py dashboard.py ./
COPY templates ./templates

# Run as a non-root user; the dashboard does no privileged work.
RUN useradd --create-home --uid 1000 avai \
 && mkdir -p /data \
 && chown -R avai:avai /data
USER avai

EXPOSE 8765

# Healthcheck: HTTP 200 on /api/notifications/new (cheap, doesn't touch
# the filesystem heavily).
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8765/api/notifications/new?since=2099-01-01', timeout=3).status==200 else 1)"

# The DB path comes from the bind-mounted /data volume defined in
# docker-compose.yml. Override at runtime with `--db` if needed.
CMD ["python", "dashboard.py", \
     "--host", "0.0.0.0", "--port", "8765", \
     "--db", "/data/host_monitor.db"]
