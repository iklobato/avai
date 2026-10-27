from __future__ import annotations

import os
import platform
import socket
from dataclasses import dataclass


@dataclass(frozen=True)
class HostIdentity:
    """Which machine and process the monitor runs as, read once at startup."""

    hostname: str
    platform: str
    pid: int

    @classmethod
    def current(cls) -> HostIdentity:
        return cls(socket.gethostname(), platform.system(), os.getpid())
