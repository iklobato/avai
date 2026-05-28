# avai

Host-security telemetry collector + LLM threat judge + read-only web
dashboard, distributed as two Docker images:

| Image | What it runs | Where it makes sense |
|---|---|---|
| `iklobato/avai:dashboard` | Read-only Flask + HTMX dashboard on port 8765 | any host — only needs the SQLite DB written by the monitor |
| `iklobato/avai:monitor` | The collector: snapshots processes, USB, launch units, file integrity, …; streams auth + exec events; writes findings classified by an LLM | **Linux hosts only** — needs `pid=host`, `network=host`, and host filesystem bind-mounts |

Everything below is Docker. Native install is also possible (`pip
install avai`) but is not the documented path.

---

## 1 — Dashboard only (any host, including macOS)

The dashboard reads a SQLite database written by the monitor (or by a
previous run). It needs no privileges, no host namespace, no
capabilities — just a directory containing `avai.db` mounted at `/data`.

```sh
mkdir -p ~/.avai && cd ~/.avai

docker run -d \
  --name avai-dashboard \
  -p 8765:8765 \
  -v "$PWD":/data \
  iklobato/avai:dashboard

open http://localhost:8765/
```

If the database doesn't exist yet, the dashboard will start but every
panel will be empty until the monitor produces some rows. Stop it with
`docker stop avai-dashboard && docker rm avai-dashboard`.

### Override the DB path or bind port

```sh
docker run --rm -p 9000:9000 \
  -v /var/lib/avai:/data \
  iklobato/avai:dashboard \
  avai dashboard --host 0.0.0.0 --port 9000 --db /data/custom.db
```

The image entry point is `avai`; anything after the image name is
passed to it.

---

## 2 — Monitor: one-shot scan (Linux host)

A single cycle on the local Linux host. No streaming, no LLM judge —
fast smoke test that the bind mounts are wired right.

```sh
mkdir -p ~/.avai && cd ~/.avai

docker run --rm \
  --pid=host \
  --network=host \
  --user 0:0 \
  --cap-add SYS_PTRACE --cap-add NET_ADMIN --cap-add NET_RAW --cap-add DAC_READ_SEARCH \
  -e HOST_PREFIX=/host \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -v /etc:/host/etc:ro \
  -v /var/lib/bluetooth:/host/var/lib/bluetooth:ro \
  -v /var/lib/dpkg:/host/var/lib/dpkg:ro \
  -v /usr/share/applications:/host/usr/share/applications:ro \
  -v /lib/systemd:/host/lib/systemd:ro \
  -v /usr/lib/systemd:/host/usr/lib/systemd:ro \
  -v /run/systemd:/run/systemd:ro \
  -v /run/dbus:/run/dbus:ro \
  -v /etc/machine-id:/etc/machine-id:ro \
  -v /dev/mapper:/dev/mapper:ro \
  -v /home:/host/home:ro \
  -v /root:/host/root:ro \
  -v "$PWD":/data \
  iklobato/avai:monitor \
  avai monitor --once --no-streaming --no-judge --db /data/avai.db
```

When the command exits, `~/.avai/avai.db` will contain one
`collection_runs` row plus the populated collector tables.

---

## 3 — Monitor: continuous, with LLM judge (Linux host)

Same bind-mounts as §2 but detached, with the LLM judge enabled. The
judge needs one credential — either `ANTHROPIC_API_KEY` (standard
Anthropic API) or `CLAUDE_CODE_OAUTH_TOKEN` (Claude Code OAuth).

```sh
mkdir -p ~/.avai && cd ~/.avai

docker run -d --name avai-monitor --restart unless-stopped \
  --pid=host --network=host --user 0:0 \
  --cap-add SYS_PTRACE --cap-add NET_ADMIN --cap-add NET_RAW --cap-add DAC_READ_SEARCH \
  -e HOST_PREFIX=/host \
  -e DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket \
  -e ANTHROPIC_API_KEY \
  -v /proc:/host/proc:ro -v /sys:/host/sys:ro -v /etc:/host/etc:ro \
  -v /var/lib/bluetooth:/host/var/lib/bluetooth:ro \
  -v /var/lib/dpkg:/host/var/lib/dpkg:ro \
  -v /usr/share/applications:/host/usr/share/applications:ro \
  -v /lib/systemd:/host/lib/systemd:ro \
  -v /usr/lib/systemd:/host/usr/lib/systemd:ro \
  -v /var/log/journal:/host/var/log/journal:ro \
  -v /var/spool/cron:/host/var/spool/cron:ro \
  -v /run/systemd:/run/systemd:ro -v /run/dbus:/run/dbus:ro \
  -v /etc/machine-id:/etc/machine-id:ro \
  -v /dev/mapper:/dev/mapper:ro \
  -v /home:/host/home:ro -v /root:/host/root:ro \
  -v "$PWD":/data \
  iklobato/avai:monitor

docker logs -f avai-monitor      # watch the cycle
```

The container will run `avai monitor` with the image's default
flags: `--interval 300 --lookback-min 6 --max-db-mb 1024
--judge-max-per-collector 60`. Override any of them by appending
your own command:

```sh
docker run ... iklobato/avai:monitor \
  avai monitor --interval 60 --max-db-mb 4096 --judge-max-per-collector 100
```

---

## 4 — Both services with docker-compose (Linux host)

`docker-compose.yml`:

```yaml
services:

  monitor:
    image: iklobato/avai:monitor
    container_name: avai-monitor
    user: "0:0"
    pid: host
    network_mode: host
    cap_add: [SYS_PTRACE, NET_ADMIN, NET_RAW, DAC_READ_SEARCH]
    environment:
      - HOST_PREFIX=/host
      - DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket
      - ANTHROPIC_API_KEY        # or CLAUDE_CODE_OAUTH_TOKEN
    volumes:
      - ./data:/data
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /etc:/host/etc:ro
      - /var/lib/bluetooth:/host/var/lib/bluetooth:ro
      - /var/lib/dpkg:/host/var/lib/dpkg:ro
      - /usr/share/applications:/host/usr/share/applications:ro
      - /lib/systemd:/host/lib/systemd:ro
      - /usr/lib/systemd:/host/usr/lib/systemd:ro
      - /var/log/journal:/host/var/log/journal:ro
      - /var/spool/cron:/host/var/spool/cron:ro
      - /run/systemd:/run/systemd:ro
      - /run/dbus:/run/dbus:ro
      - /etc/machine-id:/etc/machine-id:ro
      - /dev/mapper:/dev/mapper:ro
      - /home:/host/home:ro
      - /root:/host/root:ro
    restart: unless-stopped

  dashboard:
    image: iklobato/avai:dashboard
    container_name: avai-dashboard
    ports: ["8765:8765"]
    volumes: ["./data:/data"]
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    read_only: true
    tmpfs: [/tmp]
    restart: unless-stopped
```

Then:

```sh
mkdir -p data
export ANTHROPIC_API_KEY=sk-ant-...
docker compose up -d
docker compose logs -f monitor
open http://localhost:8765/
```

---

## 5 — Dashboard against an existing DB (any host)

If you already have an `avai.db` (produced by the monitor on a
different machine, dropped into the current directory, etc.):

```sh
docker run --rm -p 8765:8765 -v "$PWD":/data iklobato/avai:dashboard
```

The dashboard opens the file with `?mode=ro&immutable=1`, so it never
writes and never holds a lock — fine to point at a live database
being written by the monitor in another container.

---

## 6 — Common operational commands

```sh
# Inspect the bundled CLI
docker run --rm iklobato/avai:dashboard avai --help
docker run --rm iklobato/avai:dashboard avai monitor --help
docker run --rm iklobato/avai:dashboard avai dashboard --help
docker run --rm iklobato/avai:dashboard avai --version

# Stop / clean up
docker compose down                                # if using compose
docker stop avai-dashboard avai-monitor 2>/dev/null
docker rm   avai-dashboard avai-monitor 2>/dev/null

# Wipe the database (does NOT remove findings/judgments cache)
rm -f data/avai.db data/avai.db-wal data/avai.db-shm

# Pull the latest images
docker pull iklobato/avai:dashboard
docker pull iklobato/avai:monitor
```

---

## What's collected (one-line summary)

Snapshot collectors (run every cycle, default 300s):

| Group | Sources |
|---|---|
| Processes / network | `processes`, `network_connections`, `listening_ports`, `network_interfaces` (psutil) |
| Hardware | `usb_devices` (/sys/bus/usb), `bluetooth_devices` (/var/lib/bluetooth), `wifi_state` (sysfs + `iw`) |
| Persistence | `launch_items` (systemd unit files + cron) |
| Files | `file_integrity` (passwd / shadow / sudoers / SSH config / dotfiles), `setuid_files`, `mounts` |
| Apps | `installed_apps` (dpkg-query + XDG `.desktop`), `browser_extensions` |
| Posture | `system_integrity` (SELinux / AppArmor / ufw / sshd / vnc / LUKS) |

Streaming collectors (events as they happen):

| Collector | Source |
|---|---|
| `auth_events` | `journalctl -f` filtered to auth / authpriv / sshd / systemd-logind / sudo / su / polkitd |
| `process_exec_events` | `journalctl -f _AUDIT_TYPE_NAME=EXECVE` (needs auditd `auditctl -a always,exit -F arch=b64 -S execve` rule) |

For every entity collected (deduped by a content hash over the
collector's "judge fields"), the LLM judge classifies it as
`malicious` / `suspicious` / `unknown` / `benign` with a confidence,
MITRE-aligned category, and one-line remediation. Judgments are
persisted; the same artifact is never sent twice.

---

## Why no macOS in this README

The monitor relies on Linux-native facilities — `pid=host` reaching
the host's `/proc`, sysfs at `/sys/bus/usb`, `journalctl` with
`auditd`, `systemctl is-active`, `dpkg-query`, `dmsetup` for LUKS.
Docker Desktop on macOS only exposes the Linux VM that ships with
it, not the macOS host, so a containerised monitor on macOS reports
on the VM (empty/uninteresting) rather than the Mac. The dashboard
image works fine on macOS Docker — you'd just need to write the
database from somewhere else.

If you want full macOS coverage, install natively (`pip install
avai`) and run `avai monitor` with `sudo`. That's a separate path
not documented here.

---

## License

MIT — see `LICENSE`.
