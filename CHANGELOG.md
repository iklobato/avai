# Changelog

All notable changes to **avai** (PyPI: `avai-monitor`, Docker:
`iklob1/avai`). Versions follow semantic versioning.

## [0.2.6] — 2026-05-29

### Fixed
- **Dashboard showed "no run yet" for the entire first cycle.**
  `latest_run()` only returned *completed* runs, so while the monitor
  ground through its first cycle (minutes of collecting + LLM judging)
  every panel sat empty — and if the monitor was killed/restarted
  mid-cycle, it stayed empty forever. Now it prefers the latest
  completed run but **falls back to the most recent in-progress run**,
  so the dashboard shows live, partial data immediately. Steady state
  is unchanged (a completed run is still preferred → no flicker).

## [0.2.5] — 2026-05-29

### Fixed
- **LLM judge calls had no timeout — a stalled API request froze the
  whole cycle.** With the judge enabled the first cycle makes hundreds
  of LLM calls (one batch per 20 entries per collector); if any single
  request hung, the run never reached `end_run`, so it never showed as
  *completed* and the dashboard (which only lists completed runs)
  stayed empty forever. Added a 60 s per-call timeout to both the
  litellm and Anthropic-OAuth paths (`DEFAULT_JUDGE_TIMEOUT_S`); on
  timeout the batch is skipped and the cycle proceeds, so runs always
  complete and the dashboard populates.

## [0.2.4] — 2026-05-29

### Fixed
- **Ctrl-C didn't stop `avai monitor` during a cycle.** The SIGINT
  handler only set a shutdown flag (replacing Python's default
  KeyboardInterrupt), and the flag was checked only between cycles —
  so while the LLM judge ground through every collector (minutes on
  the first run), Ctrl-C was swallowed and the terminal appeared
  hung. Now: the collector loop checks the flag and stops after the
  current step on the first Ctrl-C, and a **second Ctrl-C force-quits
  immediately** (guaranteed escape hatch).

## [0.2.3] — 2026-05-28

### Fixed
- **Dashboard 500'd ("no such table") on first run against a live
  database.** The read engine used `?mode=ro&immutable=1`; `immutable=1`
  tells SQLite to ignore the `-wal` file, so when the monitor and
  dashboard start together the schema is still in the WAL (not yet
  checkpointed) and every query fails. Dropped `immutable=1` — `mode=ro`
  reads the WAL correctly. Verified it doesn't regress the Docker
  bind-mount case it was originally added for.
- **System-integrity panel mislabeled Linux data as macOS.** A row
  collected by the Linux collector (e.g. the monitor in Docker's Linux
  VM) rendered under macOS labels (FileVault, Gatekeeper…) with unset
  columns showing a false "OFF". The panel is now platform-aware and
  shows a macOS/Linux badge.

## [0.2.2] — 2026-05-28

### Fixed
- **`launch_items` collector crashed in container mode.**
  `host_paths_for_home()` returned an empty list when `HOST_PREFIX`
  was set but neither `<prefix>/home/*` nor `<prefix>/root` were
  mounted; the caller indexed `[0]` → `IndexError` killed the whole
  collector every cycle. Now iterates the returned paths (also fixes a
  latent bug where only the first user home was ever scanned).
- **CamelCase config keys were silently dropped (3 collectors).**
  Python's `configparser` lowercases keys by default, so every
  `.get("ExecStart")` / `.get("Name")` / `.get("Alias")` missed:
  - systemd units lost `program` / `keep_alive` / `user_name` /
    `run_at_load` / schedule — the LLM judge was effectively blind on
    the persistence surface.
  - `.desktop` apps lost name / version / exec.
  - BlueZ devices lost name / class.
  Fixed with `optionxform = str` on all three parsers.

### Testing
- Added `tests/test_collectors.py` and expanded the suite to 320+
  network-free unit tests across the enrichment framework, all 17
  sources, indicator extractors, HTTP client, CLI, repository + DB
  rotation, LLM-judge parsing, dashboard endpoints, and Linux
  collector file parsing. Mutation-verified: tests fail when the
  implementation breaks.

## [0.2.1] — 2026-05-28

### Fixed
- `_is_domain()` matched IPv4 literals as domains, routing IP‑host
  URLs to the wrong enrichers.
- Dashboard `_ensure_db_exists()` didn't register the enrichment
  model, so dashboard‑only containers 500'd on the
  `enrichment_evidence` table.
- `Enricher.env_token()` treated an empty‑string env var (`-e VAR=`)
  as a present token, registering keyed enrichers with no key.

## [0.2.0] — 2026-05-28

### Added
- **Threat‑intel enrichment layer** (`avai.enrichers`). Before each
  finding reaches the LLM, avai extracts indicators (SHA256, IPv4,
  domain, URL, CVE, package, OS version) and cross‑checks them against
  up to **17 external sources**, attaching the evidence to the judge's
  prompt. Results cached in SQLite with per‑source TTLs.
  - Keyless: CIRCL hashlookup, Shodan InternetDB, Feodo Tracker,
    OSV.dev, CISA KEV, NVD, endoflife.date, crt.sh.
  - One free abuse.ch key (`ABUSE_CH_AUTH_KEY`): MalwareBazaar,
    URLhaus, ThreatFox.
  - Per‑service keys: VirusTotal, AbuseIPDB, GreyNoise, Google Safe
    Browsing, PhishTank, GitHub Advisory.
- `avai monitor` flags `--no-enrich` and `--enrich-only NAME`.
- `.env.example` documenting every credential; missing keys disable a
  source cleanly.

## [0.1.0] — 2026-05-27

### Added
- Initial release: host‑security telemetry collector (21 collectors on
  macOS, 16 on Linux), LLM threat judge (litellm + Anthropic, OAuth or
  API key), and a read‑only Flask + HTMX + Chart.js dashboard.
- Single Docker image (`iklob1/avai`) with two roles — dashboard
  (default) and monitor — plus `pip install avai-monitor`.
- SQLite storage with size‑based rotation; streaming collectors for
  auth and process‑exec events.
