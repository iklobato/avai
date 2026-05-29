# Changelog

All notable changes to **avai** (PyPI: `avai-monitor`, Docker:
`iklob1/avai`). Versions follow semantic versioning.

## [0.3.0] — 2026-05-29

### Added
- **network_flows: data volume (payload bytes).** tcpdump already prints
  a per-packet payload length we were discarding — now summed per flow
  (`byte_count`) and shown as the headline traffic metric (e.g. `4.8 MB`),
  with packets/flows demoted to a detail line. Volume distinguishes a
  chatty small-packet beacon from a bulk transfer / exfil in a way a raw
  packet count can't. The summary card leads with total volume; falls
  back to packet count when bytes are unknown (older rows).
- **Process → flow attribution.** Each network flow now names the owning
  process (and pid) when resolvable. A new injectable
  `ProcessConnectionResolver` snapshots the kernel connection table
  (psutil) and correlates each flow's `(dst_ip, dst_port)` to the local
  process behind it — surfaced as a new **process** column in the
  flow table.
- **DNS query collector (`dns_queries`).** A second bounded tcpdump
  capture decodes plaintext port-53 questions (split-based, no regex)
  and aggregates them by `(qname, qtype, resolver)`. Queried domains are
  enriched against the domain threat feeds and LLM-judged. Connections to
  well-known DoH resolver endpoints on :443 are flagged (`qtype=DoH`)
  since they bypass plaintext DNS visibility. New dashboard card.
- **Persistence & tampering collectors.** `ssh_authorized_keys` (every
  key authorizing SSH login, with SHA256 fingerprint + from=/command=
  restrictions), `hosts_file` (`/etc/hosts` mappings — hijack/sinkhole
  detection), and `privilege_config` (sudoers rules, admin/wheel/sudo
  group members, UID-0 accounts). All cross-platform, surfaced in a new
  **persistence & tampering** dashboard section. Parsing is split into
  pure functions (testable) with thin IO.
- New indicator extractors wire `dns_queries` → DOMAIN and `hosts_file`
  → DOMAIN/IP into the enrichment chain. Judge hints added for all four
  collectors.

Collector coverage: macOS 22 → 26, Linux 17 → 21.

## [0.2.11] — 2026-05-29

### Added
- **network_flows: geolocation column per destination.** The
  by-destination flow table now shows where each destination IP sits —
  city / region / country plus the network owner (org / ASN). The data
  comes from the `enrichment_evidence` cache the monitor already
  populates, read through the ORM model (`_attach_ip_enrichment`); when
  several sources carry geo, the richest wins. Degrades to "no geo" when
  a destination has no cached evidence or the cache table is absent
  (older DBs).
- **New enricher: `ipwhois_geo` (ipwho.is).** Free, keyless, HTTPS IP
  geolocation so *every* public destination gets a location, not just
  threat-flagged ones. Validated live against IPv4 and IPv6. Purely
  informational — it never raises a threat verdict. AbuseIPDB
  (countryCode/isp) and Feodo (country/as_name) serve as fallbacks.
- **IPv6 destinations are now enriched + geolocated.** Added an `ipv6`
  indicator type; `NetworkFlowExtractor` emits public IPv6 destinations
  (skipping link-local / ULA / multicast), the geo enricher accepts both
  families, and the dashboard joins geo for both. The tcpdump aggregator
  already captured IPv6 (`IP6`) flows; they just weren't being enriched.
- **network_flows: resolved hostname in the destination column.** When
  any source resolved a hostname/domain for a destination IP (Shodan
  `hostnames`, AbuseIPDB `domain`), it's shown under the IP.

### Fixed
- **macOS: flows mislabelled `pktap` instead of the real interface.**
  Without `-i`, macOS tcpdump captures through the `pktap` pseudo-device
  that aggregates every interface, so all flows showed `pktap`. The
  collector now passes `-k I` so tcpdump prints the real per-packet
  interface (en0, en1, awdl0, …), and a `pktap*` listen-banner falls
  back to "unknown" rather than masking it.

## [0.2.10] — 2026-05-29

### Fixed
- **Dashboard 500 ("no such column: network_flows.iface") against a
  network_flows table written by an older monitor.** The read-only
  dashboard can't migrate the schema, so `network_flows()` now checks
  the table's columns and substitutes a NULL literal for any missing
  newer column (iface / service) instead of crashing. (`_existing_columns`.)

## [0.2.9] — 2026-05-29

### Added
- **network_flows: source interface + by-destination aggregation.**
  Flows now record the capture interface (Linux `tcpdump -i any`
  per-packet; macOS reads it from tcpdump's "listening on <iface>"
  banner). The dashboard table is now aggregated **by destination IP** —
  SUM(packets), COUNT(flows), the set of interfaces / protocols / ports,
  and the worst verdict per destination — with a summary header
  (destinations / flows / packets / malicious / suspicious).

### Fixed
- **Dashboard 500 ("no such table: network_flows") against an older
  DB.** A database written by a monitor that predates a collector lacks
  its table; the row-counts and network-flows panels now skip / empty
  out missing tables instead of crashing (`_existing_tables` guard).

## [0.2.8] — 2026-05-29

### Added
- **Network-flow aggregator collector (`network_flows`).** A new
  collector runs `tcpdump` for a bounded window each cycle and
  aggregates outbound packets into distinct `(proto, dst_ip, dst_port)`
  flows with a packet count ("top talkers"). Each new public-IP
  destination is enriched against the threat-intel sources (Feodo
  Tracker, AbuseIPDB, GreyNoise, Shodan, …) and then judged by the LLM,
  so malicious requests — C2 beacons, exfiltration, connections to
  known-bad IPs — surface as findings. Parsing is split-based (no
  regex). Requires root to capture (the monitor already runs as root).
  Collector counts are now 22 (macOS) / 17 (Linux).
- **Dashboard "network flows" table** at the bottom of the page — one
  full-width table listing each flow with its verdict, destination,
  port/service, packet count, and the LLM's reasoning.

## [0.2.7] — 2026-05-29

### Added
- **"Dismiss all" button on the dashboard toast stack.** When the
  monitor is actively judging, malicious/suspicious alerts pile up;
  previously each had to be closed individually. A "Dismiss all (N)"
  bar now appears above the stack — one click clears every toast and
  advances the alert cursor so they don't immediately re-appear on the
  next poll.

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
