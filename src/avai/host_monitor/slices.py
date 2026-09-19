"""Telemetry slices: each table the monitor writes, declared once.

A slice is the identity every OS variant of a collector shares: the name the
runner, dashboard, prompt hints and enrichment extractors key on, and the ORM
model it writes. What a collector sends to the judge (``judge_fields``) stays on
the collector class, because it differs by OS.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import (
    ArpEntryRow,
    AuthEventRow,
    BluetoothDeviceRow,
    BrowserExtensionRow,
    DiskUsageRow,
    DnsQueryRow,
    DnsResolverRow,
    FileIntegrityRow,
    FileScanRow,
    HostResourceRow,
    HostsFileRow,
    InjectionEnvRow,
    InstalledAppRow,
    KernelExtensionRow,
    KernelModuleRow,
    LaunchItemRow,
    ListeningPortRow,
    LogEntryRow,
    LoginSessionRow,
    MdmProfileRow,
    MountRow,
    NdpNeighborRow,
    NetworkConnectionRow,
    NetworkFlowRow,
    NetworkInterfaceRow,
    NetworkShareRow,
    PrivilegeConfigRow,
    ProcessExecRow,
    ProcessRow,
    PromiscuousInterfaceRow,
    ProxyConfigRow,
    QuarantineEventRow,
    RouteRow,
    SetuidFileRow,
    SshAuthorizedKeyRow,
    SshKnownHostRow,
    SystemExtensionRow,
    SystemIntegrityRow,
    TrustedRootRow,
    UsbDeviceRow,
    WifiStateRow,
    _RowBase,
)


@dataclass(frozen=True)
class Slice:
    name: str
    model: type[_RowBase]
    # Streaming slices accumulate across runs, so the dashboard counts them by
    # event time instead of by run id.
    streaming: bool = False


PROCESSES = Slice("processes", ProcessRow)
NETWORK_CONNECTIONS = Slice("network_connections", NetworkConnectionRow)
NETWORK_FLOWS = Slice("network_flows", NetworkFlowRow)
DNS_QUERIES = Slice("dns_queries", DnsQueryRow)
SSH_AUTHORIZED_KEYS = Slice("ssh_authorized_keys", SshAuthorizedKeyRow)
HOSTS_FILE = Slice("hosts_file", HostsFileRow)
PRIVILEGE_CONFIG = Slice("privilege_config", PrivilegeConfigRow)
LISTENING_PORTS = Slice("listening_ports", ListeningPortRow)
NETWORK_INTERFACES = Slice("network_interfaces", NetworkInterfaceRow)
USB_DEVICES = Slice("usb_devices", UsbDeviceRow)
BLUETOOTH_DEVICES = Slice("bluetooth_devices", BluetoothDeviceRow)
WIFI_STATE = Slice("wifi_state", WifiStateRow)
LAUNCH_ITEMS = Slice("launch_items", LaunchItemRow)
QUARANTINE_EVENTS = Slice("quarantine_events", QuarantineEventRow)
BROWSER_EXTENSIONS = Slice("browser_extensions", BrowserExtensionRow)
SYSTEM_INTEGRITY = Slice("system_integrity", SystemIntegrityRow)
AUTH_EVENTS = Slice("auth_events", AuthEventRow, streaming=True)
FILE_INTEGRITY = Slice("file_integrity", FileIntegrityRow)
FILE_SCAN = Slice("file_scan", FileScanRow)
INSTALLED_APPS = Slice("installed_apps", InstalledAppRow)
PROCESS_EXEC_EVENTS = Slice("process_exec_events", ProcessExecRow, streaming=True)
MOUNTS = Slice("mounts", MountRow)
SETUID_FILES = Slice("setuid_files", SetuidFileRow)
MDM_PROFILES = Slice("mdm_profiles", MdmProfileRow)
KERNEL_EXTENSIONS = Slice("kernel_extensions", KernelExtensionRow)
SYSTEM_EXTENSIONS = Slice("system_extensions", SystemExtensionRow)
HOST_RESOURCES = Slice("host_resources", HostResourceRow)
DISK_USAGE = Slice("disk_usage", DiskUsageRow)
LOG_ENTRIES = Slice("log_entries", LogEntryRow)
DNS_RESOLVERS = Slice("dns_resolvers", DnsResolverRow)
ARP_TABLE = Slice("arp_table", ArpEntryRow)
NDP_NEIGHBORS = Slice("ndp_neighbors", NdpNeighborRow)
ROUTES = Slice("routes", RouteRow)
PROXY_CONFIG = Slice("proxy_config", ProxyConfigRow)
NETWORK_SHARES = Slice("network_shares", NetworkShareRow)
LOGIN_SESSIONS = Slice("login_sessions", LoginSessionRow)
PROMISCUOUS_IFACES = Slice("promiscuous_ifaces", PromiscuousInterfaceRow)
TRUSTED_ROOTS = Slice("trusted_roots", TrustedRootRow)
INJECTION_ENV = Slice("injection_env", InjectionEnvRow)
KERNEL_MODULES = Slice("kernel_modules", KernelModuleRow)
SSH_KNOWN_HOSTS = Slice("ssh_known_hosts", SshKnownHostRow)

ALL: tuple[Slice, ...] = (
    PROCESSES,
    NETWORK_CONNECTIONS,
    NETWORK_FLOWS,
    DNS_QUERIES,
    SSH_AUTHORIZED_KEYS,
    HOSTS_FILE,
    PRIVILEGE_CONFIG,
    LISTENING_PORTS,
    NETWORK_INTERFACES,
    USB_DEVICES,
    BLUETOOTH_DEVICES,
    WIFI_STATE,
    LAUNCH_ITEMS,
    QUARANTINE_EVENTS,
    BROWSER_EXTENSIONS,
    SYSTEM_INTEGRITY,
    AUTH_EVENTS,
    FILE_INTEGRITY,
    FILE_SCAN,
    INSTALLED_APPS,
    PROCESS_EXEC_EVENTS,
    MOUNTS,
    SETUID_FILES,
    MDM_PROFILES,
    KERNEL_EXTENSIONS,
    SYSTEM_EXTENSIONS,
    HOST_RESOURCES,
    DISK_USAGE,
    LOG_ENTRIES,
    DNS_RESOLVERS,
    ARP_TABLE,
    NDP_NEIGHBORS,
    ROUTES,
    PROXY_CONFIG,
    NETWORK_SHARES,
    LOGIN_SESSIONS,
    PROMISCUOUS_IFACES,
    TRUSTED_ROOTS,
    INJECTION_ENV,
    KERNEL_MODULES,
    SSH_KNOWN_HOSTS,
)
