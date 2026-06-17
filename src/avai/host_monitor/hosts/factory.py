"""The single platform-detection point.

``platform.system()`` is read here and nowhere else. Its result is
resolved to a concrete :class:`Host` and then discarded — the rest of the
package holds a ``Host`` and calls methods on it, never re-checking the
OS. An unsupported platform fails loudly here instead of crashing deep
inside a tool invocation meant for a different OS.
"""

from __future__ import annotations

import platform

from .capabilities import Host


class HostFactory:
    """Resolve the host for the current (or a named) platform.

    Concrete hosts are imported lazily so importing this module doesn't
    drag in every OS adapter, and so a host module that imports an
    OS-only library degrades only when actually selected.
    """

    @staticmethod
    def create(system: str | None = None) -> Host:
        name = system if system is not None else platform.system()
        if name == "Darwin":
            from .macos import MacOSHost

            return MacOSHost()
        if name == "Linux":
            from .linux import LinuxHost

            return LinuxHost()
        if name == "Windows":
            from .windows import WindowsHost

            return WindowsHost()
        raise RuntimeError(f"avai has no host implementation for platform: {name!r}")
