"""The single platform-detection point.

``platform.system()`` is read here and nowhere else. Its result is
resolved to a concrete :class:`Host` and then discarded: the rest of the
package holds a ``Host`` and calls methods on it, never re-checking the
OS. An unsupported platform fails loudly here instead of crashing deep
inside a tool invocation meant for a different OS.
"""

from __future__ import annotations

import logging
import platform

from .capabilities import Host
from .linux import LinuxHost
from .macos import MacOSHost
from .windows import WindowsHost


class UnsupportedPlatformError(RuntimeError):
    """avai has no host implementation for this platform."""


class HostFactory:
    """Resolve the host for the current (or a named) platform."""

    HOSTS = (("Darwin", MacOSHost), ("Linux", LinuxHost), ("Windows", WindowsHost))

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def create(self, system: str | None = None) -> Host:
        name = system if system is not None else platform.system()
        host_class = dict(self.HOSTS).get(name)
        if host_class is None:
            raise UnsupportedPlatformError(
                f"avai has no host implementation for platform: {name!r}"
            )
        return host_class.create(self._logger)
