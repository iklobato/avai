# avai — multi-stage image, package-installed
#
# Both final stages `pip install .` the wheel built from the source
# tree, so the `avai` entry point ends up on PATH inside the image.
#
#   base       — Python + the source tree → wheel install. Used
#                directly by neither stage; both finals FROM base.
#   dashboard  — slim, non-root. CMD: `avai dashboard ...`
#   monitor    — adds iw / systemd / dmsetup / bluez. Root user.
#                CMD: `avai monitor ...`
#
# docker-compose.yml picks one per service via `build.target`.

ARG PYTHON_VERSION=3.11


# ---------------------------------------------------------------------------
# base — install the avai wheel + its required deps + judge extras
# ---------------------------------------------------------------------------

FROM python:${PYTHON_VERSION}-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Copy build inputs first so the layer caches when only docs/configs
# change. `[judge]` extra pulls litellm + anthropic for the LLM judge.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install '.[judge]'


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

CMD ["avai", "dashboard", \
     "--host", "0.0.0.0", "--port", "8765", \
     "--db", "/data/avai.db"]


# ---------------------------------------------------------------------------
# monitor — adds the Linux userland the host-monitoring collectors call.
# ---------------------------------------------------------------------------

FROM base AS monitor

RUN apt-get update && apt-get install -y --no-install-recommends \
        iw \
        systemd \
        dbus \
        dmsetup \
        bluez \
        dpkg \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

HEALTHCHECK --interval=60s --timeout=4s --start-period=30s --retries=3 \
  CMD test -f /data/avai.db

CMD ["avai", "monitor", \
     "--db", "/data/avai.db", \
     "--interval", "300", \
     "--lookback-min", "6", \
     "--max-db-mb", "1024", \
     "--judge-max-per-collector", "60"]
