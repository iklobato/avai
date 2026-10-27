"""Injectable runtime collaborators.

These are the cohesive, stateful (or seam-bearing) objects that the rest
of the package depends on instead of reaching for module-level helper
functions: the single subprocess seam (:class:`CommandRunner`), the
injectable clock (:class:`Clock`), the hashing collaborator
(:class:`Digest`) and the external-SQLite reader
(:class:`ExternalSqliteReader`).

Collectors and per-OS adapters receive these via their constructors, so
tests can pass fakes (a ``CommandRunner`` returning canned tool output, a
``FrozenClock``) without spawning processes or depending on wall-clock
time.
"""

from __future__ import annotations

from .clock import Clock, FrozenClock
from .coerce import Coerce
from .command_runner import CommandRunner
from .digest import Digest
from .host_identity import HostIdentity
from .host_io import HostIo
from .host_paths import HostPaths
from .mounts import (
    HostPart,
    HostRootfs,
    HostUsage,
    MountField,
    MountTable,
    StatvfsUsage,
)
from .probes import (
    DiskMetrics,
    LaunchdServiceSupervisor,
    PortInspector,
    ProcessInspector,
    PsutilConnections,
    PsutilPortInspector,
    PsutilProcessInspector,
    ServiceSupervisor,
    SystemdServiceSupervisor,
    SystemMetrics,
    TriState,
)
from .row_source import CommandSnapshot, FileSnapshot, RowParser, RowSource
from .sqlite_reader import ExternalSqliteReader
from .stream_source import JsonLineStreamSource, LineParser

__all__ = [
    "Clock",
    "FrozenClock",
    "Coerce",
    "CommandRunner",
    "Digest",
    "HostIdentity",
    "HostIo",
    "HostPaths",
    "PsutilConnections",
    "SystemMetrics",
    "DiskMetrics",
    "ServiceSupervisor",
    "LaunchdServiceSupervisor",
    "SystemdServiceSupervisor",
    "PortInspector",
    "PsutilPortInspector",
    "ProcessInspector",
    "PsutilProcessInspector",
    "TriState",
    "HostPart",
    "HostRootfs",
    "HostUsage",
    "MountField",
    "MountTable",
    "StatvfsUsage",
    "CommandSnapshot",
    "FileSnapshot",
    "RowParser",
    "RowSource",
    "ExternalSqliteReader",
    "JsonLineStreamSource",
    "LineParser",
]
