"""Host filesystem access, with container-path translation.

Groups the path-building and low-level file reads the collectors need:
``HOST_PREFIX`` translation (so a containerised monitor reads the host's
bind-mounted tree), ``~`` expansion, and the sysfs/plist readers. Pure
filesystem access with no subprocess — exposed as static methods so it
has one cohesive home instead of scattered module functions.
"""

from __future__ import annotations

import os
import plistlib
from pathlib import Path
from typing import Optional

from .. import constants


class HostPaths:
    """Path resolution + low-level reads under container translation."""

    @staticmethod
    def translate(p) -> Path:
        """Translate an absolute host path to its in-container location
        when HOST_PREFIX is set. Relative paths and the empty-prefix case
        are passthroughs."""
        p = p if isinstance(p, Path) else Path(p)
        if not constants.HOST_PREFIX or not p.is_absolute():
            return p
        return Path(constants.HOST_PREFIX + str(p))

    @staticmethod
    def expand(p: str) -> Path:
        return Path(os.path.expanduser(p))

    @staticmethod
    def for_home(template: str) -> list[Path]:
        """Expand a ``~/<rest>`` template into actual paths.

        Without HOST_PREFIX: ``~/<rest>`` → ``[expanduser(template)]``.
        With HOST_PREFIX (container mode): one entry per user home found
        under ``<prefix>/home/*`` plus ``<prefix>/root`` for the rest.
        Absolute paths pass through :meth:`translate` (always one path) so
        callers can flatten freely.
        """
        if not template.startswith("~/"):
            return [HostPaths.translate(template)]
        rest = template[2:]
        if not constants.HOST_PREFIX:
            return [Path(os.path.expanduser(template))]
        out: list[Path] = []
        home_root = Path(constants.HOST_PREFIX) / "home"
        if home_root.is_dir():
            try:
                for user_dir in home_root.iterdir():
                    if user_dir.is_dir():
                        out.append(user_dir / rest)
            except OSError:
                pass
        root_home = Path(constants.HOST_PREFIX) / "root"
        if root_home.is_dir():
            out.append(root_home / rest)
        return out

    @staticmethod
    def read_sysfs(path: Path, encoding: str = "utf-8") -> Optional[str]:
        """Read a sysfs/procfs attribute file. Returns the stripped string
        or None if unreadable. Doesn't raise on permission errors."""
        try:
            return path.read_text(encoding=encoding, errors="replace").strip()
        except (OSError, UnicodeError):
            return None

    @staticmethod
    def read_plist(path: Path) -> Optional[dict]:
        """Parse a binary/XML plist; None if unreadable or not a dict."""
        try:
            with open(path, "rb") as f:
                data = plistlib.load(f)
        except (OSError, plistlib.InvalidFileException, ValueError):
            return None
        return data if isinstance(data, dict) else None
