# avai/host_monitor

macOS host security telemetry collector with an optional LLM threat judge.

Captures structured snapshots of host state — processes, network sockets,
USB / Bluetooth / Wi-Fi, launch agents, TCC permissions, quarantine
events, browser extensions, system integrity, auth events, file
integrity, installed apps — into a local SQLite database (SQLAlchemy
ORM). An optional LLM layer (via [litellm](https://github.com/BerriAI/litellm))
classifies each unique entity once with a verdict and MITRE-aligned
threat category.

No regex, no text-parsing — every source is consumed in its structured
form (JSON, plist, reflected SQLite). All LLM prompts live in an
external TOML file so you can tune them without touching code.


## Requirements

- macOS 12+ (Monterey or newer — `log show --style ndjson` and
  `system_profiler -json` are required)
- Python 3.11+ (for `tomllib`, `StrEnum`)
- `psutil` (required)
- `sqlalchemy >= 2.0` (required)
- `litellm` (optional — only needed if you want LLM threat judging)
- A provider API key (e.g. `ANTHROPIC_API_KEY`) — optional, only for
  the LLM judge

```sh
pip install psutil 'sqlalchemy>=2.0' litellm
```


## Quick start

```sh
cd ~/scripts/avai

# one-shot collection, no LLM judge
python3 host_monitor.py --once --no-judge

# continuous collection every 5 minutes, with LLM judge
export ANTHROPIC_API_KEY=sk-ant-...
python3 host_monitor.py --interval 300

# full visibility (root, plus grant the Terminal Full Disk Access)
sudo -E python3 host_monitor.py --interval 300
```


## Docker

Only the **dashboard** is containerised. The collector (`host_monitor.py`)
runs natively on the macOS host — its data sources are
macOS-host-only userland (`system_profiler`, `log stream`, `launchctl`,
`TCC.db`, native `psutil` process visibility) and a Linux container
running inside Docker Desktop's VM cannot reach them. Even with
`--privileged --pid=host --network=host`, the container sees the
Linux VM rather than your Mac.

So the topology is:

```
  macOS host                      |  docker (linux container)
  ─────────────────────────────── | ─────────────────────────────
  host_monitor.py (sudo)          |
       ↓                          |
  ./host_monitor.db  ⇐ bind mount ⇒  dashboard.py (Flask, read-only)
                                  |       ↓
                                  |  http://localhost:8765
```

### Run the dashboard in Docker

```sh
cd ~/scripts/avai
docker compose up -d --build
open http://localhost:8765
```

That builds `avai-dashboard:latest`, bind-mounts the current directory
to `/data` inside the container, exposes the dashboard on host port
8765, and runs a healthcheck against `/api/notifications/new`.

The default `docker compose up` runs **only the dashboard** — the
monitor service is opt-in via the `linux` profile (next section).

### Run BOTH services in Docker (Linux hosts only)

On a Linux host (bare metal, KVM, or a real Linux server — *not*
macOS Docker Desktop), bring up both the monitor and the dashboard:

```sh
# from a real Linux host, with credentials in the environment
export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...   # or ANTHROPIC_API_KEY
docker compose --profile linux up -d --build
```

The `--profile linux` flag activates the `monitor` service, which:

- runs as root (needed for `psutil.net_connections` cross-process socket
  visibility);
- shares the host's PID and network namespaces (`pid: host`,
  `network_mode: host`) so it observes host processes/sockets;
- adds `SYS_PTRACE`, `NET_ADMIN`, `NET_RAW` capabilities;
- bind-mounts `/proc`, `/sys`, `/etc`, `/var/log`, `/home` read-only;
- writes to the same SQLite DB the dashboard reads.

Collector coverage on Linux (Phases 1 + 2 + 3 + 4):

| Collector | Linux |
|---|---|
| processes, network_connections, listening_ports, network_interfaces | ✓ (psutil) |
| file_integrity | ✓ (Linux paths: `/etc/{passwd,shadow,sudoers,crontab}`, `~/.bashrc`, SSH config, …) |
| browser_extensions | ✓ (XDG paths: `~/.config/google-chrome`, `~/.mozilla/firefox`, …) |
| installed_apps | ✓ (`dpkg-query -W` + `/usr/share/applications/*.desktop`) |
| launch_items | ✓ (systemd unit / timer files + `/etc/crontab` + `/etc/cron.d` + `/var/spool/cron`) |
| auth_events (streaming) | ✓ (`journalctl -f --output=json`, filtered to auth/authpriv + sshd / systemd-logind / sudo / su / polkitd) |
| usb_devices | ✓ (`/sys/bus/usb/devices` sysfs walk, reading vendor/product/serial/manufacturer attribute files) |
| bluetooth_devices | ✓ (`/var/lib/bluetooth/<adapter>/<mac>/info` INI files via configparser) |
| wifi_state | ✓ (sysfs `/sys/class/net/<iface>/wireless` + `iw dev <iface> link` for SSID/BSSID/freq) |
| system_integrity | ✓ (LUKS dm-crypt mappings → FileVault-equivalent; SELinux+AppArmor → Gatekeeper-equivalent; ufw OR firewalld → firewall; sshd / x11vnc systemctl states) |
| **mounts** | ✓ (psutil.disk_partitions(all=True) — tmpfs-over-/etc rootkit detection) |
| **setuid_files** | ✓ (walk /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/{bin,sbin}, /usr/libexec, /opt looking for st_mode & 04000/02000) |
| **process_exec_events (streaming)** | ✓ (`journalctl -f --output=json _AUDIT_TYPE_NAME=EXECVE + SYSCALL` — requires auditd execve rule on host) |
| tcc_permissions, quarantine_events | ✗ (no Linux equivalents) |
| mdm_profiles, kernel_extensions, system_extensions | ✗ (macOS-only concepts) |

The mapping uses the existing `system_integrity` row schema — its
macOS-named columns (`filevault_active`, `gatekeeper_assessments_enabled`,
`remote_login_enabled`, etc.) keep their semantic intent on Linux:

| macOS column | Linux semantic |
|---|---|
| `filevault_active` | any active dm-crypt mapping |
| `firewall_global_state` | ufw OR firewalld running |
| `gatekeeper_assessments_enabled` | SELinux Enforcing OR AppArmor enabled |
| `remote_login_enabled` | `ssh.service` / `sshd.service` active |
| `screen_sharing_enabled`, `remote_management_enabled` | `x11vnc` / `vncserver` / `xrdp` active |

### Container permissions reference

The monitor container needs to read the host's filesystem and call
host-level CLI tools (`systemctl`, `journalctl`, `dpkg-query`,
`dmsetup`, `iw`). Two coordinated mechanisms make that work:

1. **`HOST_PREFIX` env var** — collectors translate every absolute
   host path they read through a `host_path()` helper. With
   `HOST_PREFIX=/host`, `/etc/passwd` becomes `/host/etc/passwd`;
   `~/.config/google-chrome` expands to one entry per user home
   discovered under `/host/home/*`.

2. **Native-path mounts for CLI tools** — `systemctl` (D-Bus to
   `/run/systemd/private`) and `dmsetup` (ioctl on
   `/dev/mapper/control`) hardcode their lookup paths. Those get
   bind-mounted at the same path inside the container, not under
   `/host`.

Bind-mount matrix:

| Mount | Used by | Path inside container |
|---|---|---|
| `/sys` | `LinuxUsbDevicesCollector`, `LinuxWifiCollector`, `LinuxSystemIntegrityCollector` (SELinux + AppArmor) | `/host/sys` |
| `/etc` | `LinuxLaunchItemsCollector` (systemd unit overrides + cron), `LinuxSystemIntegrityCollector` (ufw.conf), `FileIntegrityCollector` (passwd / shadow / sudoers / ssh config) | `/host/etc` |
| `/var/lib/bluetooth` | `LinuxBluetoothCollector` | `/host/var/lib/bluetooth` |
| `/var/lib/dpkg` | `LinuxInstalledAppsCollector` (`dpkg-query --admindir`) | `/host/var/lib/dpkg` |
| `/usr/share/applications` + `/usr/local/share/applications` + `/var/lib/flatpak/exports/share/applications` | `LinuxInstalledAppsCollector` (.desktop entries) | `/host/usr/...` |
| `/lib/systemd`, `/usr/lib/systemd` | `LinuxLaunchItemsCollector` (vendor unit files) | `/host/lib/systemd`, `/host/usr/lib/systemd` |
| `/var/log/journal`, `/run/log/journal` | `LinuxAuthEventsCollector` (`journalctl --directory`) | `/host/var/log/journal` etc. |
| `/var/spool/cron` | `LinuxLaunchItemsCollector` (per-user crontabs) | `/host/var/spool/cron` |
| `/home`, `/root` | `BrowserExtensionsCollector`, `FileIntegrityCollector` (`~/.ssh`, `~/.bashrc`, browser profiles) | `/host/home`, `/host/root` |
| `/run/systemd` | `systemctl` (CLI from `LinuxSystemIntegrityCollector`) | `/run/systemd` (native path) |
| `/run/dbus` | `systemctl` D-Bus connection | `/run/dbus` (native path) |
| `/etc/machine-id` | `journalctl` (needs matching machine ID) | `/etc/machine-id` (native path) |
| `/dev/mapper` | `dmsetup` ioctl | `/dev/mapper` (native path) |

Linux capabilities added (root in a container has a *limited* default
cap set — Docker drops several at start):

| Capability | Why |
|---|---|
| `SYS_PTRACE` | `psutil.net_connections()` cross-process socket visibility, `/proc/<pid>` reads for other processes |
| `NET_ADMIN` | `iw dev <iface> link` netlink (NL80211); some sysfs read permissions |
| `NET_RAW` | Auxiliary network introspection |
| `DAC_READ_SEARCH` | Read files owned by other users (e.g. `/etc/shadow`, root-only `/var/lib/bluetooth`) without depending on Linux DAC override behaviour for the root user inside a container |

Namespaces shared with host:

| Namespace | Setting | Why |
|---|---|---|
| PID | `pid: host` | `psutil` sees host processes, `/proc/<pid>` reads the host's view |
| Network | `network_mode: host` | `psutil.net_connections`, `iw dev` (NL80211), `journalctl` host log access |

Mounts deliberately *not* added (kept inside the container's own
namespace): IPC namespace, UTS namespace, user namespace,
`/var/run/docker.sock`. The monitor doesn't need to call back into
Docker or share IPC with the host.

### Dashboard hardening

Flags applied in `docker-compose.yml` for the dashboard service:

- `read_only: true` — root filesystem mounted read-only (with `/tmp`
  as tmpfs for Flask's session cache).
- `cap_drop: [ALL]` and `security_opt: no-new-privileges:true` — the
  dashboard doesn't need any Linux capability.
- Non-root runtime user (`uid 1000`).
- The bind mount is the project directory; the dashboard application
  only issues `SELECT` queries against the SQLite DB.

The host's `host_monitor.py` writes the database; SQLite's WAL mode
permits the container to read concurrently. Refreshing the dashboard
or letting the HTMX polling cycle run will pick up new judgements
within seconds of the host writing them.

### Why the monitor can't be containerised on macOS

| Collector | Needs |
|---|---|
| `processes`, `network_connections`, `listening_ports`, `network_interfaces` | native `psutil` against the macOS kernel (a Linux container sees the Docker VM, not macOS) |
| `usb_devices`, `bluetooth_devices`, `wifi_state` | `system_profiler` (macOS binary) + IOKit |
| `launch_items` | reads `/Library/LaunchAgents`, `/Library/LaunchDaemons`, `~/Library/LaunchAgents` — bind-mountable but unhelpful without `launchctl` |
| `tcc_permissions` | reads `TCC.db` (macOS Privacy database, plus the running terminal needs Full Disk Access) |
| `quarantine_events` | reads `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` (macOS LaunchServices) |
| `system_integrity` | `fdesetup`, `spctl`, `launchctl`, `/Library/Preferences/com.apple.alf.plist` |
| `auth_events` (streaming) | `log stream --style ndjson` (macOS unified log, no Linux equivalent) |
| `browser_extensions`, `file_integrity`, `installed_apps` | bind-mountable in principle, but no value without the others |

If you want full coverage, run the monitor natively:

```sh
sudo -E /Users/$(whoami)/.pyenv/versions/3.11.7/bin/python3 \
  ~/scripts/avai/host_monitor.py --interval 300 --max-db-mb 1024
```

…and grant your Terminal **Full Disk Access** in System Settings →
Privacy & Security → Full Disk Access for the TCC collector.

### Stop / rebuild / inspect

```sh
docker compose ps                       # status + healthcheck
docker compose logs -f dashboard        # tail logs
docker compose restart dashboard        # restart after a code change
docker compose down                     # stop and remove
docker compose up -d --build            # rebuild + restart
```

By default the database is written to `./host_monitor.db` next to the
script. Prompts are read from `./host_monitor_prompts.toml`.


## CLI parameters

| Flag | Default | Purpose |
|---|---|---|
| `--db PATH` | `./host_monitor.db` (next to the script) | Where to write the SQLite database. Parent directory is created if missing. |
| `--once` | off | Run a single collection cycle and exit. Without this, the script loops forever on the `--interval`. |
| `--interval N` | `300` (seconds) | Seconds between cycles when running continuously. Each cycle is one full pass over every collector. |
| `--lookback-min N` | `6` (minutes) | How far back the `auth_events` collector reads from the unified log per cycle. Should be slightly larger than `--interval / 60` to avoid gaps; default 6 min covers a 5 min cycle plus margin. |
| `--no-judge` | off | Disable the LLM threat judge entirely. Raw telemetry is still collected. Use this if you don't have an API key or want to avoid LLM cost. |
| `--judge-model ID` | `claude-haiku-4-5-20251001` | litellm model identifier. Any model litellm supports works — `gpt-4o-mini`, `claude-sonnet-4-6`, `openai/gpt-4o`, etc. The corresponding provider API key must be set (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, …). |
| `--judge-batch-size N` | `20` | How many entries per LLM call. Lower = more calls but smaller prompts; higher = fewer calls but larger prompts. Tune by latency and the model's context window. |
| `--judge-max-per-collector N` | `200` | Hard cap on how many new entries the judge will classify per collector per run. Prevents a first-time run from sending thousands of items in one go. Remaining entries are picked up by the next run. |
| `--prompts-file PATH` | `./host_monitor_prompts.toml` (next to the script) | Path to the TOML file holding the system prompt, the user-prompt template, and the per-collector hints. See "Prompts file" below. |
| `--verbose` | off | Enable DEBUG-level logging. |

Logs go to stderr in UTC with the format `YYYY-MM-DD HH:MM:SSZ LEVEL message`.


## Permissions

Three collectors need elevated access for full coverage. Without them
they record their failure in the `collector_errors` table and the run
continues:

| Collector | Needs | Without it |
|---|---|---|
| `network_connections` | `sudo` | Only sees this script's own sockets (no cross-process visibility) |
| `listening_ports` | `sudo` | Same as above |
| `tcc_permissions` | Terminal/agent has **Full Disk Access** | Cannot read `TCC.db` (raises `PermissionError`) |

To grant Full Disk Access: System Settings → Privacy & Security →
Full Disk Access → enable for **Terminal** (or whatever runs Python).

For continuous root-mode collection, use `sudo -E` to preserve your
API key environment variable:

```sh
sudo -E python3 host_monitor.py --interval 300
```


## LLM threat judge

When enabled, the judge:

1. After each collector writes its rows, the Runner asks the Sink which
   `content_hash` values from this run have no judgment yet.
2. Those unjudged entries (deduped by content) are sent to the LLM in
   batches of `--judge-batch-size`, with a per-collector cap of
   `--judge-max-per-collector`.
3. The LLM returns one judgment per entry: `verdict`, `category`,
   `confidence`, `reasoning`.
4. Judgments are stored in the `judgements` table keyed by `(content_hash,
   collector)`. The same entity is judged exactly once across all runs.

### Verdicts

| Verdict | Meaning |
|---|---|
| `benign` | Expected on a developer Mac |
| `suspicious` | Anomaly worth review; not necessarily malicious |
| `malicious` | Likely active threat |
| `unknown` | Insufficient information to decide |

### Categories (MITRE-ATT&CK-aligned)

`none`, `persistence`, `privilege_escalation`, `defense_evasion`,
`credential_access`, `discovery`, `lateral_movement`, `collection`,
`command_and_control`, `exfiltration`, `impact`, `initial_access`,
`execution`, `reconnaissance`.

### Which collectors are judged

| Collector | Judged | Why |
|---|---|---|
| `processes` | yes | Dedup by `(name, exe, cmdline, username)` |
| `network_connections` | **no** | Too high churn; aggregate behaviourally instead |
| `listening_ports` | yes | Dedup by `(process_name, addr, port)` |
| `network_interfaces` | **no** | Counters need behavioural analysis |
| `usb_devices` | yes | Dedup by `(name, vendor_id, product_id, manufacturer)` |
| `bluetooth_devices` | yes | Dedup by `(name, address, minor_type)` |
| `wifi_state` | yes | Dedup by `(ssid, bssid, security)` |
| `launch_items` | yes | Persistence is the primary signal |
| `tcc_permissions` | yes | Dedup by `(scope, service, client, auth_value)` |
| `quarantine_events` | yes | Dedup by `(agent_bundle_id, agent_name, urls)` |
| `browser_extensions` | yes | Dedup by `(browser, ext_id, name, permissions)` |
| `system_integrity` | yes | Single-row but very high signal |
| `auth_events` | **no** | Per-event judgment is too noisy |
| `file_integrity` | yes | Watched dotfiles + `/etc` configs |
| `installed_apps` | yes | Dedup by `(bundle_id, name, path)` |


## Prompts file

`host_monitor_prompts.toml` holds **every** string sent to the LLM:

- `[judge].system` — the system prompt. Uses `string.Template`
  substitutions: `$verdicts` and `$categories` are filled at load time
  from the enums defined in the script. Edit this string to change
  the model's overall instructions.
- `[judge].user_template` — the per-batch user-prompt template. Uses
  substitutions: `$collector`, `$hints`, `$entries`.
- `[collector_hints].<name>` — per-collector guidance about what to
  flag. The keys must match each collector's `name` attribute
  (`processes`, `launch_items`, `usb_devices`, …). To disable a hint,
  set it to an empty string `""`.

Edit the TOML file, save, and re-run the script. No code changes
needed.


## Database

Single SQLite file (default `avai/host_monitor.db`). WAL mode is enabled
so reads don't block the writer.

### Core tables

| Table | What it holds |
|---|---|
| `collection_runs` | One row per cycle (run_id, started/finished, hostname, ok/failed counts, lookback). |
| `collector_errors` | Per-cycle errors raised by individual collectors (collector name, error class, message). |
| `judgements` | LLM judgments keyed by `(content_hash, collector)`. Stores verdict, category, confidence, reasoning, model, created_at. |

### Per-collector tables

`processes`, `network_connections`, `listening_ports`,
`network_interfaces`, `usb_devices`, `bluetooth_devices`, `wifi_state`,
`launch_items`, `tcc_permissions`, `quarantine_events`,
`browser_extensions`, `system_integrity`, `auth_events`,
`file_integrity`, `installed_apps`.

Every collector row carries:
- `id` — autoincrement primary key
- `run_id` — foreign key into `collection_runs`
- `collected_at` — UTC timestamp string
- `content_hash` — stable SHA-256 over the collector's
  `judge_fields`. NULL when judging is disabled for that collector.

Join judgments by `content_hash`:

```sql
SELECT li.label, li.path, j.verdict, j.category, j.reasoning
FROM launch_items li
LEFT JOIN judgements j
       ON j.content_hash = li.content_hash
      AND j.collector    = 'launch_items'
WHERE li.run_id = (SELECT run_id FROM collection_runs
                   ORDER BY started_at DESC LIMIT 1);
```

### Useful queries

Latest run summary:

```sql
SELECT * FROM collection_runs ORDER BY started_at DESC LIMIT 1;
```

Anything not classified `benign` in the latest run, across all
collectors:

```sql
SELECT collector, verdict, category, confidence, reasoning
FROM judgements
WHERE verdict != 'benign'
ORDER BY confidence DESC;
```

First-seen launch items in the latest run (items whose `content_hash`
never appeared before):

```sql
SELECT path, label
FROM launch_items
WHERE run_id = (SELECT run_id FROM collection_runs
                ORDER BY started_at DESC LIMIT 1)
  AND content_hash NOT IN (
    SELECT content_hash FROM launch_items
    WHERE run_id != (SELECT run_id FROM collection_runs
                     ORDER BY started_at DESC LIMIT 1)
  );
```

New outbound destinations seen, grouped by process:

```sql
SELECT pid, raddr_ip, raddr_port, COUNT(*) AS n
FROM network_connections
WHERE status = 'ESTABLISHED' AND raddr_ip IS NOT NULL
GROUP BY pid, raddr_ip, raddr_port
ORDER BY n DESC;
```


## Architecture (one-screen overview)

Five abstractions:

- **Collector** — one slice of host state. Owns a SQLAlchemy model and
  declares `judge_fields` + `judge_hints`. Yields plain dict rows from
  `collect()`. Adding a new dimension of monitoring = one new class.
- **Model** — SQLAlchemy 2.0 ORM class per collector table. Schema
  (columns, indexes, types) lives here.
- **Sink** — repository over a SQLAlchemy `Engine`. Owns DDL bootstrap,
  run lifecycle, row writes, judgment writes, and "what is unjudged"
  lookups. No raw SQL anywhere.
- **Judge** — `LlmJudge` calls litellm; `NullJudge` is the no-op
  fallback. Returns `Judgment` dataclasses.
- **Runner** — orchestrates the pipeline: per-collector transaction,
  error capture, `content_hash` injection, judge invocation,
  scheduling.

Strategy pattern for browser extensions
(`ChromiumExtensionReader` / `FirefoxExtensionReader`) keeps the
Chromium-vs-Firefox layout difference pluggable.


## Files in this folder

```
host_monitor.py             — the collector + judge + runner
host_monitor_prompts.toml   — all LLM prompts (system, user template, per-collector hints)
host_monitor.db             — SQLite database (gitignored; created on first run)
host_monitor.db-shm/-wal    — SQLite WAL sidecars (gitignored)
.gitignore                  — ignores DBs, caches, virtualenvs
README.md                   — this file
```


## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Many `AuthenticationError` lines in the log | `--no-judge` not set and no API key. Either `export ANTHROPIC_API_KEY=…` or pass `--no-judge`. |
| `collector=network_connections status=failed error=PermissionError` | Expected without root. Run with `sudo -E …` for cross-process socket visibility. |
| `collector=tcc_permissions status=failed error=PermissionError` | Grant Full Disk Access to the running terminal/agent. |
| `database is locked` | Don't run two collectors against the same DB at once. WAL mode allows concurrent **readers** while a writer is running, but not two writers. |
| Slow first cycle | `auth_events` and judging can dominate the first cycle. Subsequent cycles are fast because `content_hash` dedup means almost nothing new to judge. |
