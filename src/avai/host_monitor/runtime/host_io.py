from __future__ import annotations

from dataclasses import dataclass

from .command_runner import CommandRunner
from .host_paths import HostPaths


@dataclass(frozen=True)
class HostIo:
    """The two seams a collector uses to read the host: external commands
    and (container-translated) files."""

    runner: CommandRunner
    paths: HostPaths
