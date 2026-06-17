# avai — single image, two roles, run together.
#
# Same image is used for both `avai dashboard` and `avai monitor`. The
# monitor's Linux userland (iw, systemctl, journalctl, dmsetup, bluez)
# is included unconditionally — adds ~80 MB but keeps the publish/pull
# story to one image per architecture.
#
# Default CMD runs BOTH the monitor and the dashboard under supervisord,
# so the dashboard is populated out of the box:
#
#   docker run -p 8765:8765 -v "$PWD":/data iklob1/avai
#
# For full host visibility on Linux, add --pid=host --network=host.
# Override the command to run a single role instead:
#
#   docker run -p 8765:8765 -v "$PWD":/data iklob1/avai avai dashboard
#   docker run --pid=host --network=host ... iklob1/avai avai monitor

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

# avai itself, plus supervisord to run the two roles together.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install '.' supervisor \
 && mkdir -p /data
COPY docker/supervisord.conf /etc/supervisor/avai.conf

EXPOSE 8765

# Healthcheck targets the dashboard. It's a no-op for the monitor
# role (no port listening), but `docker run` / compose treats a
# 30 s-interval failing healthcheck as just a non-healthy container —
# the monitor still runs. If you want a green healthcheck on the
# monitor role too, override with `--no-healthcheck` at run time.
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8765/api/notifications/new?since=2099-01-01', timeout=3).status==200 else 1)"

# Default = monitor + dashboard together, via supervisord. Override with
# `avai dashboard` / `avai monitor ...` to run a single role.
CMD ["supervisord", "-c", "/etc/supervisor/avai.conf"]
