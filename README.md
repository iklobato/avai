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
