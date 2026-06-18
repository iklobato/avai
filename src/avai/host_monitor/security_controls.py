"""Security-control detection — the proper-abstraction layer for the
system-integrity topics.

A :class:`SecurityControl` answers two questions about one topic:

* ``enabled`` — *posture*: is the service configured to be reachable? (the
  thing a security panel must never miss — an exposed SSH that's idle).
* ``active``  — *behaviour*: is it actually in use right now? (the
  "webcam-in-use" signal — a live session).

Each control composes small injected capabilities (a
:class:`ServiceManager`, :class:`PortInspector`, :class:`ProcessInspector`)
rather than shelling out itself, so the OS differences live entirely in the
injected strategy and the same control class works on macOS / Linux /
Windows. Topics are assembled per OS at the composition root (the host
module), exactly like the RowSource collectors elsewhere.

Values are tri-state ``1`` / ``0`` / ``None`` (on / off / unknown), matching
the existing ``system_integrity`` columns and probe convention.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol

from .runtime import PortInspector, ProcessInspector, ServiceManager, tri_or


@dataclass(frozen=True)
class IntegrityFinding:
    """One topic's posture + behaviour, with the signal that decided it."""

    topic: str
    enabled: Optional[int]
    active: Optional[int]
    source: str


class SecurityControl(Protocol):
    """Detects exactly one security topic. Substitutable across platforms."""

    topic: str

    def inspect(self) -> IntegrityFinding: ...


@dataclass(frozen=True)
class ServiceSpec:
    """The OS-agnostic identity of a managed network service: how the service
    manager names it, the port it exposes, and the process that serves it.
    Pure data — the only thing that varies between SSH / Screen Sharing / ARD
    and between operating systems."""

    topic: str
    unit: str
    port: int
    process: str


class NetworkServiceControl:
    """Posture + behaviour for a socket-activated network service (SSH,
    Screen Sharing, ARD/RDP), on any OS.

    ``enabled`` = the service manager reports it enabled **or** something is
    listening on its port — so an enabled-but-idle daemon (whose process
    isn't running yet) is never reported "off". ``active`` = the daemon
    process is running **or** a peer is connected. This replaces the old
    ``pgrep``-only check, which conflated "in use right now" with "enabled"
    and therefore hid idle-but-exposed services.
    """

    def __init__(
        self,
        spec: ServiceSpec,
        services: ServiceManager,
        ports: PortInspector,
        processes: ProcessInspector,
    ) -> None:
        self._spec = spec
        self._services = services
        self._ports = ports
        self._processes = processes

    @property
    def topic(self) -> str:
        return self._spec.topic

    def inspect(self) -> IntegrityFinding:
        spec = self._spec
        enabled = tri_or(
            self._services.enabled(spec.unit),
            self._ports.listening(spec.port),
        )
        active = tri_or(
            self._processes.running(spec.process),
            self._ports.established(spec.port),
        )
        return IntegrityFinding(
            topic=spec.topic,
            enabled=enabled,
            active=active,
            source="service+port+process",
        )
