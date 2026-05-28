# avai — single image, two roles.
#
# Same image is used for both `avai dashboard` and `avai monitor`. The
# monitor's Linux userland (iw, systemctl, journalctl, dmsetup, bluez)
# is included unconditionally — adds ~80 MB but keeps the publish/pull
# story to one image per architecture.
#
# Default CMD is the dashboard (most common standalone use). Override
# the command at `docker run` / compose level to invoke the monitor:
#
#   docker run -p 8765:8765 -v "$PWD":/data iklobato/avai
#   docker run --pid=host --network=host ... iklobato/avai \
#       avai monitor --db /data/avai.db

ARG PYTHON_VERSION=3.11
FROM python:${PYTHON_VERSION}-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Monitor's runtime deps. Kept on a single layer so the cache key is
# stable as long as this list doesn't change.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iw \
        systemd \
        dbus \
        dmsetup \
        bluez \
        dpkg \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# avai itself.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install '.[judge]' \
 && mkdir -p /data

EXPOSE 8765

# Healthcheck targets the dashboard. It's a no-op for the monitor
# role (no port listening), but `docker run` / compose treats a
# 30 s-interval failing healthcheck as just a non-healthy container —
# the monitor still runs. If you want a green healthcheck on the
# monitor role too, override with `--no-healthcheck` at run time.
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8765/api/notifications/new?since=2099-01-01', timeout=3).status==200 else 1)"

# Default = dashboard. Override with `avai monitor ...` for the
# collector role.
CMD ["avai", "dashboard", \
     "--host", "0.0.0.0", "--port", "8765", \
     "--db", "/data/avai.db"]
