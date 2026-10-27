"""Collector groups every host assembles the same way."""

from __future__ import annotations

import logging

from ..collectors import (
    DiskUsageCollector,
    HostResourcesCollector,
    HostsFileCollector,
    ListeningPortsCollector,
    MountsCollector,
    NetworkConnectionsCollector,
    NetworkInterfacesCollector,
    PrivilegeConfigCollector,
    ProcessCollector,
    SnapshotCollector,
    SshAuthorizedKeysCollector,
)
from ..persistence_collectors import SshKnownHostsCollector
from ..prompts import Prompts
from ..runtime import (
    Clock,
    DiskMetrics,
    HostPaths,
    PsutilConnections,
    SystemMetrics,
)
from .capabilities import FilesystemLayout, PrivilegedAccounts


class PortableCollectors:
    """The psutil-backed collectors, identical on every OS."""

    def __init__(self, logger: logging.Logger, paths: HostPaths) -> None:
        self._logger = logger
        self._paths = paths

    def build(self, prompts: Prompts) -> list[SnapshotCollector]:
        hint = prompts.hint_for
        metrics, connections = SystemMetrics(), PsutilConnections()
        disks = DiskMetrics(self._logger, self._paths)
        return [
            ProcessCollector(metrics, hint("processes")),
            NetworkConnectionsCollector(connections, hint("network_connections")),
            ListeningPortsCollector(connections, hint("listening_ports")),
            NetworkInterfacesCollector(metrics, hint("network_interfaces")),
            HostResourcesCollector(metrics, Clock(), hint("host_resources")),
            DiskUsageCollector(disks, hint("disk_usage")),
            MountsCollector(disks, hint("mounts")),
        ]


class AccountCollectors:
    """The collectors that read per-OS paths and privileged accounts through
    the host's capability ports."""

    def __init__(self, fs: FilesystemLayout, accounts: PrivilegedAccounts) -> None:
        self._fs = fs
        self._accounts = accounts

    def build(self, prompts: Prompts) -> list[SnapshotCollector]:
        hint = prompts.hint_for
        return [
            SshAuthorizedKeysCollector(self._fs, hint("ssh_authorized_keys")),
            HostsFileCollector(self._fs, hint("hosts_file")),
            PrivilegeConfigCollector(
                self._fs, self._accounts, hint("privilege_config")
            ),
            SshKnownHostsCollector(self._fs, hint("ssh_known_hosts")),
        ]
