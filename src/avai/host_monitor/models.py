"""SQLAlchemy ORM models — the database schema."""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class CollectionRun(Base):
    __tablename__ = "collection_runs"
    run_id: Mapped[str] = mapped_column(primary_key=True)
    # Indexed: latest_run / prior_run / recent_runs all ORDER BY started_at
    # and are called by nearly every dashboard fragment.
    started_at: Mapped[str] = mapped_column(index=True)
    finished_at: Mapped[Optional[str]]
    hostname: Mapped[str]
    collectors_ok: Mapped[int] = mapped_column(default=0)
    collectors_failed: Mapped[int] = mapped_column(default=0)
    lookback_min: Mapped[int]


class CollectorErrorRow(Base):
    __tablename__ = "collector_errors"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(index=True)
    collector: Mapped[str]
    error_class: Mapped[Optional[str]]
    message: Mapped[Optional[str]]
    occurred_at: Mapped[str]


class Judgement(Base):
    __tablename__ = "judgements"
    content_hash: Mapped[str] = mapped_column(primary_key=True)
    collector: Mapped[str] = mapped_column(primary_key=True, index=True)
    verdict: Mapped[str] = mapped_column(index=True)
    category: Mapped[Optional[str]]
    confidence: Mapped[Optional[float]]
    reasoning: Mapped[Optional[str]]
    remediation: Mapped[Optional[str]]
    model: Mapped[str]
    # Indexed: overview judged/cost sums, /api/notifications/new and the
    # verdict chart all filter judgements by created_at.
    created_at: Mapped[str] = mapped_column(index=True)
    # Most recent snapshot run timestamp at which this content_hash was
    # observed. Compared to the latest run's started_at to derive whether
    # the underlying artifact is still present ("active") or has gone
    # away ("resolved"). NULL until the next snapshot cycle touches it.
    last_seen_at: Mapped[Optional[str]] = mapped_column(index=True)
    # Behavioural context captured at judge time, surfaced on the finding:
    #   novel        — 1 if the artifact first appeared after the host's
    #                  baseline was established (per-host-baseline signal).
    #   context_json — JSON {"baseline": {...}, "related": {...}} where
    #                  `related` is the correlated process story (ports /
    #                  flows / connections / DNS / exec lineage).
    novel: Mapped[Optional[int]] = mapped_column(index=True)
    context_json: Mapped[Optional[str]]
    # Estimated USD cost of judging this artifact (its share of the LLM
    # batch call). NULL for judgments written before cost tracking existed.
    cost_usd: Mapped[Optional[float]]


class IncidentNarrativeRow(Base):
    """One LLM-written incident digest synthesising the host's active
    non-benign findings into a single attack-story. The dashboard shows
    the most recent row. ``finding_hashes`` is the sorted JSON list of the
    finding content_hashes the narrative covered — compared cycle-to-cycle
    so we only regenerate when the active-finding set actually changes."""

    __tablename__ = "incident_narratives"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[str] = mapped_column(index=True)
    run_id: Mapped[Optional[str]]
    model: Mapped[str]
    severity: Mapped[str]
    headline: Mapped[str]
    # Short prose summary (1-2 sentences). The detailed story is structured.
    summary: Mapped[Optional[str]]
    # JSON arrays the dashboard renders as a vertical timeline + action cards:
    #   timeline_json: [{"time","title","category","detail"}]
    #   actions_json:  [{"priority","title","command","detail"}]
    timeline_json: Mapped[Optional[str]]
    actions_json: Mapped[Optional[str]]
    # Legacy freeform fields — kept nullable for back-compat with rows
    # written before the structured format; new rows leave them empty.
    narrative: Mapped[Optional[str]]
    recommended_actions: Mapped[Optional[str]]
    finding_count: Mapped[int] = mapped_column(default=0)
    finding_hashes: Mapped[Optional[str]]


class RiskScoreRow(Base):
    """One deterministic host posture score per run, for the trended grade
    widget. ``drivers_json`` is the list of point-costing factors;
    ``explanation`` describes the change vs the previous run."""

    __tablename__ = "risk_scores"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[str] = mapped_column(index=True)
    run_id: Mapped[Optional[str]]
    score: Mapped[int]
    grade: Mapped[str]
    prev_score: Mapped[Optional[int]]
    drivers_json: Mapped[Optional[str]]
    explanation: Mapped[Optional[str]]


class StreamingSession(Base):
    """One row per StreamingWorker lifetime. Rows produced by a streaming
    collector reference this via ``run_id`` (same column as snapshot
    rows reference ``collection_runs.run_id`` — both are UUIDs, the
    foreign-key relationship is loose by design)."""

    __tablename__ = "streaming_sessions"
    run_id: Mapped[str] = mapped_column(primary_key=True)
    collector: Mapped[str] = mapped_column(index=True)
    hostname: Mapped[str]
    started_at: Mapped[str]
    finished_at: Mapped[Optional[str]]
    row_count: Mapped[int] = mapped_column(default=0)


class _RowBase(Base):
    """Common columns for every collector table."""

    __abstract__ = True
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(index=True)
    collected_at: Mapped[str]
    content_hash: Mapped[Optional[str]] = mapped_column(index=True)


class ProcessRow(_RowBase):
    __tablename__ = "processes"
    pid: Mapped[int]
    ppid: Mapped[Optional[int]]
    name: Mapped[Optional[str]] = mapped_column(index=True)
    exe: Mapped[Optional[str]]
    cmdline_json: Mapped[Optional[str]]
    username: Mapped[Optional[str]]
    uid: Mapped[Optional[int]]
    status: Mapped[Optional[str]]
    create_time: Mapped[Optional[float]]
    cpu_percent: Mapped[Optional[float]]
    memory_rss: Mapped[Optional[int]]
    num_fds: Mapped[Optional[int]]
    num_threads: Mapped[Optional[int]]


class NetworkConnectionRow(_RowBase):
    __tablename__ = "network_connections"
    pid: Mapped[Optional[int]]
    family: Mapped[Optional[str]]
    type: Mapped[Optional[str]]
    laddr_ip: Mapped[Optional[str]]
    laddr_port: Mapped[Optional[int]]
    raddr_ip: Mapped[Optional[str]] = mapped_column(index=True)
    raddr_port: Mapped[Optional[int]]
    status: Mapped[Optional[str]]


class ListeningPortRow(_RowBase):
    __tablename__ = "listening_ports"
    pid: Mapped[Optional[int]]
    process_name: Mapped[Optional[str]]
    family: Mapped[Optional[str]]
    type: Mapped[Optional[str]]
    laddr_ip: Mapped[Optional[str]]
    laddr_port: Mapped[Optional[int]]


class NetworkFlowRow(_RowBase):
    """One aggregated network flow observed by the tcpdump aggregator:
    a distinct (proto, dst_ip, dst_port) seen during the capture window,
    with how many packets matched it."""

    __tablename__ = "network_flows"
    iface: Mapped[Optional[str]]  # capture interface (e.g. en0, eth0)
    proto: Mapped[Optional[str]]
    dst_ip: Mapped[Optional[str]] = mapped_column(index=True)
    dst_port: Mapped[Optional[int]]
    service: Mapped[Optional[str]]  # well-known name for dst_port, if any
    packets: Mapped[Optional[int]]
    byte_count: Mapped[Optional[int]]  # summed payload bytes (tcpdump length)
    process: Mapped[Optional[str]]  # owning process name, if resolvable
    pid: Mapped[Optional[int]]  # owning process pid, if resolvable
    first_seen: Mapped[Optional[str]]
    last_seen: Mapped[Optional[str]]


class NetworkInterfaceRow(_RowBase):
    __tablename__ = "network_interfaces"
    name: Mapped[str]
    is_up: Mapped[Optional[int]]
    speed_mbps: Mapped[Optional[int]]
    mtu: Mapped[Optional[int]]
    bytes_sent: Mapped[Optional[int]]
    bytes_recv: Mapped[Optional[int]]
    packets_sent: Mapped[Optional[int]]
    packets_recv: Mapped[Optional[int]]
    errin: Mapped[Optional[int]]
    errout: Mapped[Optional[int]]
    dropin: Mapped[Optional[int]]
    dropout: Mapped[Optional[int]]
    addresses_json: Mapped[Optional[str]]


class UsbDeviceRow(_RowBase):
    __tablename__ = "usb_devices"
    name: Mapped[Optional[str]]
    vendor_id: Mapped[Optional[str]]
    product_id: Mapped[Optional[str]]
    serial_number: Mapped[Optional[str]]
    manufacturer: Mapped[Optional[str]]
    location_id: Mapped[Optional[str]]
    speed: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]


class BluetoothDeviceRow(_RowBase):
    __tablename__ = "bluetooth_devices"
    name: Mapped[Optional[str]]
    address: Mapped[Optional[str]]
    connected: Mapped[Optional[int]]
    paired: Mapped[Optional[int]]
    minor_type: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]


class WifiStateRow(_RowBase):
    __tablename__ = "wifi_state"
    interface: Mapped[Optional[str]]
    ssid: Mapped[Optional[str]]
    bssid: Mapped[Optional[str]]
    channel: Mapped[Optional[str]]
    security: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]


class LaunchItemRow(_RowBase):
    __tablename__ = "launch_items"
    scope: Mapped[str]
    path: Mapped[str] = mapped_column(index=True)
    label: Mapped[Optional[str]] = mapped_column(index=True)
    program: Mapped[Optional[str]]
    program_arguments_json: Mapped[Optional[str]]
    run_at_load: Mapped[Optional[int]]
    keep_alive: Mapped[Optional[int]]
    start_interval: Mapped[Optional[int]]
    start_calendar_interval_json: Mapped[Optional[str]]
    user_name: Mapped[Optional[str]]
    group_name: Mapped[Optional[str]]
    sha256: Mapped[Optional[str]]
    mtime: Mapped[Optional[float]]
    raw_json: Mapped[Optional[str]]


class QuarantineEventRow(_RowBase):
    __tablename__ = "quarantine_events"
    event_id: Mapped[Optional[str]]
    timestamp: Mapped[Optional[float]]
    agent_bundle_id: Mapped[Optional[str]]
    agent_name: Mapped[Optional[str]]
    origin_url: Mapped[Optional[str]]
    data_url: Mapped[Optional[str]]
    sender_name: Mapped[Optional[str]]
    type_number: Mapped[Optional[int]]


class BrowserExtensionRow(_RowBase):
    __tablename__ = "browser_extensions"
    browser: Mapped[Optional[str]]
    profile: Mapped[Optional[str]]
    extension_id: Mapped[Optional[str]] = mapped_column(index=True)
    name: Mapped[Optional[str]]
    version: Mapped[Optional[str]]
    permissions_json: Mapped[Optional[str]]
    host_permissions_json: Mapped[Optional[str]]
    path: Mapped[Optional[str]]
    manifest_json: Mapped[Optional[str]]


class SystemIntegrityRow(_RowBase):
    __tablename__ = "system_integrity"
    filevault_active: Mapped[Optional[int]]
    firewall_global_state: Mapped[Optional[int]]
    firewall_stealth: Mapped[Optional[int]]
    firewall_logging: Mapped[Optional[int]]
    gatekeeper_assessments_enabled: Mapped[Optional[int]]
    remote_login_enabled: Mapped[Optional[int]]
    screen_sharing_enabled: Mapped[Optional[int]]
    remote_management_enabled: Mapped[Optional[int]]
    raw_json: Mapped[Optional[str]]


class AuthEventRow(_RowBase):
    __tablename__ = "auth_events"
    event_timestamp: Mapped[Optional[str]] = mapped_column(index=True)
    process: Mapped[Optional[str]]
    subsystem: Mapped[Optional[str]]
    category: Mapped[Optional[str]]
    event_type: Mapped[Optional[str]]
    event_message: Mapped[Optional[str]]
    pid: Mapped[Optional[int]]
    raw_json: Mapped[Optional[str]]


class FileIntegrityRow(_RowBase):
    __tablename__ = "file_integrity"
    path: Mapped[str] = mapped_column(index=True)
    sha256: Mapped[Optional[str]]
    size: Mapped[Optional[int]]
    mtime: Mapped[Optional[float]]
    mode: Mapped[Optional[int]]
    uid: Mapped[Optional[int]]
    gid: Mapped[Optional[int]]
    exists_flag: Mapped[Optional[int]]


class InstalledAppRow(_RowBase):
    __tablename__ = "installed_apps"
    path: Mapped[str]
    bundle_id: Mapped[Optional[str]] = mapped_column(index=True)
    name: Mapped[Optional[str]]
    version: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]


class ProcessExecRow(_RowBase):
    """One row per process exec event from eslogger (macOS) or
    auditd-via-journalctl (Linux). Same shape both sides so the
    dashboard treats them identically."""

    __tablename__ = "process_exec_events"
    event_timestamp: Mapped[Optional[str]] = mapped_column(index=True)
    event_type: Mapped[Optional[str]]
    pid: Mapped[Optional[int]]
    ppid: Mapped[Optional[int]]
    uid: Mapped[Optional[int]]
    username: Mapped[Optional[str]]
    exe_path: Mapped[Optional[str]] = mapped_column(index=True)
    exe_args_json: Mapped[Optional[str]]
    parent_path: Mapped[Optional[str]]
    signing_id: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]


class MountRow(_RowBase):
    __tablename__ = "mounts"
    device: Mapped[Optional[str]]
    mountpoint: Mapped[Optional[str]] = mapped_column(index=True)
    fstype: Mapped[Optional[str]]
    opts: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]


class SetuidFileRow(_RowBase):
    __tablename__ = "setuid_files"
    path: Mapped[Optional[str]] = mapped_column(index=True)
    mode: Mapped[Optional[int]]
    uid: Mapped[Optional[int]]
    gid: Mapped[Optional[int]]
    size: Mapped[Optional[int]]
    mtime: Mapped[Optional[float]]
    sha256: Mapped[Optional[str]]
    setuid: Mapped[Optional[int]]
    setgid: Mapped[Optional[int]]
    raw_json: Mapped[Optional[str]]


class MdmProfileRow(_RowBase):
    __tablename__ = "mdm_profiles"
    identifier: Mapped[Optional[str]] = mapped_column(index=True)
    display_name: Mapped[Optional[str]]
    organization: Mapped[Optional[str]]
    description: Mapped[Optional[str]]
    install_date: Mapped[Optional[str]]
    profile_scope: Mapped[Optional[str]]
    is_supervised: Mapped[Optional[int]]
    raw_json: Mapped[Optional[str]]


class KernelExtensionRow(_RowBase):
    __tablename__ = "kernel_extensions"
    bundle_id: Mapped[Optional[str]] = mapped_column(index=True)
    name: Mapped[Optional[str]]
    version: Mapped[Optional[str]]
    path: Mapped[Optional[str]]
    team_id: Mapped[Optional[str]]
    signing_id: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]


class SystemExtensionRow(_RowBase):
    __tablename__ = "system_extensions"
    bundle_id: Mapped[Optional[str]] = mapped_column(index=True)
    team_id: Mapped[Optional[str]]
    version: Mapped[Optional[str]]
    state: Mapped[Optional[str]]
    categories: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]


class DnsQueryRow(_RowBase):
    """One distinct DNS question observed during the capture window
    (port-53 plaintext), or a detected DoH endpoint. ``qname`` is the
    queried domain — enriched against the domain threat feeds."""

    __tablename__ = "dns_queries"
    iface: Mapped[Optional[str]]
    qname: Mapped[Optional[str]] = mapped_column(index=True)
    qtype: Mapped[Optional[str]]  # A, AAAA, … or "DoH"
    server_ip: Mapped[Optional[str]]  # resolver the query went to
    process: Mapped[Optional[str]]
    count: Mapped[Optional[int]]
    first_seen: Mapped[Optional[str]]
    last_seen: Mapped[Optional[str]]


class SshAuthorizedKeyRow(_RowBase):
    """One entry in an ``authorized_keys`` file — a credential that grants
    SSH login. A *new* key is a classic persistence backdoor."""

    __tablename__ = "ssh_authorized_keys"
    path: Mapped[Optional[str]] = mapped_column(index=True)
    owner: Mapped[Optional[str]]  # the account this key authorizes
    key_type: Mapped[Optional[str]]  # ssh-ed25519, ssh-rsa, …
    fingerprint: Mapped[Optional[str]] = mapped_column(index=True)  # sha256
    comment: Mapped[Optional[str]]
    options: Mapped[Optional[str]]  # forced-command / from= restrictions


class HostsFileRow(_RowBase):
    """One mapping in ``/etc/hosts``. Hijacking entries (pointing a real
    domain at an attacker IP, or 0.0.0.0-ing a security domain) are a
    cheap, high-impact tampering technique."""

    __tablename__ = "hosts_file"
    source_path: Mapped[Optional[str]]
    ip: Mapped[Optional[str]] = mapped_column(index=True)
    hostnames: Mapped[Optional[str]]  # space-joined names on the line


class PrivilegeConfigRow(_RowBase):
    """One privilege-granting fact: a sudoers rule, an admin/wheel/sudo
    group member, or a login-capable / UID-0 account. New entries here
    are privilege-escalation persistence."""

    __tablename__ = "privilege_config"
    kind: Mapped[Optional[str]] = mapped_column(index=True)  # sudoers|group|account
    subject: Mapped[Optional[str]]  # user / group / rule owner
    detail: Mapped[Optional[str]]  # the rule, member list, uid/shell
    source_path: Mapped[Optional[str]]


# ---------------------------------------------------------------------------
# Network neighborhood & topology (Tier 1)
# ---------------------------------------------------------------------------


class ArpEntryRow(_RowBase):
    """One ARP (IPv4 neighbor) cache entry. A new MAC for a known IP — the
    gateway especially — is a classic ARP-spoof / rogue-device signal."""

    __tablename__ = "arp_table"
    ip: Mapped[Optional[str]] = mapped_column(index=True)
    mac: Mapped[Optional[str]] = mapped_column(index=True)
    interface: Mapped[Optional[str]]
    flags: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]


class NdpNeighborRow(_RowBase):
    """One IPv6 NDP neighbor-cache entry (the v6 analog of ARP)."""

    __tablename__ = "ndp_neighbors"
    ip: Mapped[Optional[str]] = mapped_column(index=True)
    mac: Mapped[Optional[str]] = mapped_column(index=True)
    interface: Mapped[Optional[str]]
    state: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]


class RouteRow(_RowBase):
    """One routing-table entry. A changed default route or an added static
    route is route-hijack / redirection persistence."""

    __tablename__ = "routes"
    destination: Mapped[Optional[str]] = mapped_column(index=True)
    gateway: Mapped[Optional[str]] = mapped_column(index=True)
    interface: Mapped[Optional[str]]
    flags: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]


class DnsResolverRow(_RowBase):
    """One configured DNS resolver. A nameserver swapped to an attacker IP
    is a cheap, high-impact DNS hijack."""

    __tablename__ = "dns_resolvers"
    server: Mapped[Optional[str]] = mapped_column(index=True)
    scope: Mapped[Optional[str]]
    search: Mapped[Optional[str]]
    interface: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]


# ---------------------------------------------------------------------------
# Network exposure & MITM surface (Tier 2)
# ---------------------------------------------------------------------------


class ProxyConfigRow(_RowBase):
    """A configured proxy / PAC. A silently-set proxy is MITM / exfil."""

    __tablename__ = "proxy_config"
    scope: Mapped[Optional[str]] = mapped_column(index=True)  # http|https|pac|...
    host: Mapped[Optional[str]] = mapped_column(index=True)
    port: Mapped[Optional[str]]
    pac_url: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]


class LoginSessionRow(_RowBase):
    """An active login session. A remote source is a live operator."""

    __tablename__ = "login_sessions"
    user: Mapped[Optional[str]] = mapped_column(index=True)
    tty: Mapped[Optional[str]]
    source: Mapped[Optional[str]] = mapped_column(index=True)  # remote host/IP or local
    login_at: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]


class NetworkShareRow(_RowBase):
    """A mounted network share (SMB/NFS/…) — lateral movement / staging."""

    __tablename__ = "network_shares"
    remote: Mapped[Optional[str]] = mapped_column(index=True)
    mountpoint: Mapped[Optional[str]]
    fstype: Mapped[Optional[str]]
    options: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]


class PromiscuousInterfaceRow(_RowBase):
    """An interface's promiscuous flag — promisc=1 means a sniffer."""

    __tablename__ = "promiscuous_ifaces"
    interface: Mapped[Optional[str]] = mapped_column(index=True)
    promiscuous: Mapped[Optional[int]] = mapped_column(index=True)
    flags: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]


class TrustedRootRow(_RowBase):
    """A trusted root CA. A new non-standard root enables TLS interception
    / fake code-signing."""

    __tablename__ = "trusted_roots"
    subject: Mapped[Optional[str]] = mapped_column(index=True)
    fingerprint: Mapped[Optional[str]] = mapped_column(index=True)
    source: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]


# ---------------------------------------------------------------------------
# Host persistence / injection (Tier 3)
# ---------------------------------------------------------------------------


class InjectionEnvRow(_RowBase):
    """A library-injection setting (DYLD_INSERT_LIBRARIES / LD_PRELOAD /
    AppInit_DLLs). Any value here is code-injection persistence."""

    __tablename__ = "injection_env"
    scope: Mapped[Optional[str]] = mapped_column(index=True)
    variable: Mapped[Optional[str]]
    value: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]


class KernelModuleRow(_RowBase):
    """A loaded kernel module (Linux/Windows driver). A new/unsigned module
    can be a rootkit."""

    __tablename__ = "kernel_modules"
    name: Mapped[Optional[str]] = mapped_column(index=True)
    size: Mapped[Optional[str]]
    used_by: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]


class HostResourceRow(_RowBase):
    """One snapshot of the host's aggregate resource meters — memory, swap,
    CPU, load average, uptime, task/thread counts — the top-of-``htop``
    panel. One row per collection cycle. A continuous metric, not a discrete
    artifact, so it isn't LLM-judged (``judge_enabled=False``); the
    dashboard trends it instead. Per-OS-only fields (buffers/cached on
    Linux, wired on macOS, iowait on Linux) are nullable."""

    __tablename__ = "host_resources"
    # Memory (bytes, except *_percent)
    mem_total: Mapped[Optional[int]]
    mem_available: Mapped[Optional[int]]
    mem_used: Mapped[Optional[int]]
    mem_free: Mapped[Optional[int]]
    mem_percent: Mapped[Optional[float]]
    mem_active: Mapped[Optional[int]]
    mem_inactive: Mapped[Optional[int]]
    mem_buffers: Mapped[Optional[int]]
    mem_cached: Mapped[Optional[int]]
    mem_wired: Mapped[Optional[int]]
    # Swap
    swap_total: Mapped[Optional[int]]
    swap_used: Mapped[Optional[int]]
    swap_free: Mapped[Optional[int]]
    swap_percent: Mapped[Optional[float]]
    # CPU (percentages over the sample window) + per-core JSON list
    cpu_percent: Mapped[Optional[float]]
    cpu_user: Mapped[Optional[float]]
    cpu_system: Mapped[Optional[float]]
    cpu_idle: Mapped[Optional[float]]
    cpu_iowait: Mapped[Optional[float]]
    cpu_per_core_json: Mapped[Optional[str]]
    cpu_count_physical: Mapped[Optional[int]]
    cpu_count_logical: Mapped[Optional[int]]
    # Load average + uptime
    load_1: Mapped[Optional[float]]
    load_5: Mapped[Optional[float]]
    load_15: Mapped[Optional[float]]
    boot_time: Mapped[Optional[float]]
    uptime_seconds: Mapped[Optional[int]]
    # Task/thread tallies
    tasks_total: Mapped[Optional[int]]
    tasks_running: Mapped[Optional[int]]
    threads_total: Mapped[Optional[int]]


class DiskUsageRow(_RowBase):
    """One mounted filesystem's capacity + (best-effort) per-device I/O
    counters — the ``df`` table. One row per filesystem per cycle. Like
    :class:`HostResourceRow`, a continuous metric (not LLM-judged)."""

    __tablename__ = "disk_usage"
    device: Mapped[Optional[str]]
    mountpoint: Mapped[Optional[str]] = mapped_column(index=True)
    fstype: Mapped[Optional[str]]
    opts: Mapped[Optional[str]]
    total: Mapped[Optional[int]]
    used: Mapped[Optional[int]]
    free: Mapped[Optional[int]]
    percent: Mapped[Optional[float]]
    io_read_bytes: Mapped[Optional[int]]
    io_write_bytes: Mapped[Optional[int]]
    io_read_count: Mapped[Optional[int]]
    io_write_count: Mapped[Optional[int]]


class SshKnownHostRow(_RowBase):
    """A host pinned in a user's ``known_hosts`` — reveals pivot targets and
    can hide a ProxyCommand backdoor."""

    __tablename__ = "ssh_known_hosts"
    host: Mapped[Optional[str]] = mapped_column(index=True)
    key_type: Mapped[Optional[str]]
    fingerprint: Mapped[Optional[str]] = mapped_column(index=True)
    source_path: Mapped[Optional[str]]
    raw_json: Mapped[Optional[str]]
