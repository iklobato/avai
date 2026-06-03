"""Per-OS host abstractions.

A ``Host`` is the single object the rest of the package talks to about
platform-specific behaviour. It is resolved exactly once, by
:class:`HostFactory`, from ``platform.system()`` — after that nothing
branches on the OS. The host owns:

* its **capability ports** — narrow objects (:class:`FilesystemLayout`,
  :class:`PrivilegedAccounts`) that supply the OS-varying facts and row
  sources the collectors need, injected into those collectors so the
  collectors themselves carry no OS knowledge; and
* its **collector set** — which snapshot/streaming collectors run on this
  OS, assembled in :meth:`Host.snapshot_collectors` /
  :meth:`Host.streaming_collectors`.

A capability a given OS lacks is expressed by *not* assembling the
collector that needs it — never by a runtime ``if`` or a port that raises.
"""

from __future__ import annotations

from .capabilities import FilesystemLayout, Host, PrivilegedAccounts
from .factory import HostFactory

__all__ = [
    "Host",
    "FilesystemLayout",
    "PrivilegedAccounts",
    "HostFactory",
]
