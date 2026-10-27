from __future__ import annotations

import os
import plistlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from xml.parsers.expat import ExpatError

HOME_PREFIX = "~/"


class HostPaths:
    """Path resolution + low-level reads under container translation.

    ``prefix`` is where the host's root is mounted inside a container
    (``HOST_PREFIX``, e.g. ``/host``); empty when the monitor runs on the
    host itself."""

    PREFIX_ENV = "HOST_PREFIX"

    def __init__(self, prefix: str) -> None:
        self._prefix = prefix

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> HostPaths:
        return cls(environ.get(cls.PREFIX_ENV, "").rstrip("/"))

    def in_container(self) -> bool:
        return bool(self._prefix)

    def under_prefix(self, relative: str) -> Path:
        """``relative`` inside the host mount (``<prefix>/<relative>``)."""
        return Path(self._prefix) / relative

    def translate(self, raw: Any) -> Path:
        """Translate an absolute host path (a ``str`` or ``Path``) to its
        in-container location when HOST_PREFIX is set. Relative paths and
        the empty-prefix case are passthroughs."""
        path = Path(raw)
        if not self._prefix or not path.is_absolute():
            return path
        return Path(self._prefix + str(path))

    def expand(self, raw: str) -> Path:
        return Path(os.path.expanduser(raw))

    def for_home(self, template: str) -> list[Path]:
        """Expand a ``~/<rest>`` template into actual paths.

        Without HOST_PREFIX: ``~/<rest>`` → ``[expanduser(template)]``.
        With HOST_PREFIX (container mode): one entry per user home found
        under ``<prefix>/home/*`` plus ``<prefix>/root`` for the rest.
        Absolute paths pass through :meth:`translate` (always one path) so
        callers can flatten freely.
        """
        if not template.startswith(HOME_PREFIX):
            return [self.translate(template)]
        if not self._prefix:
            return [self.expand(template)]
        rest = template.removeprefix(HOME_PREFIX)
        homes = self._container_homes()
        return [home / rest for home in homes]

    def read_sysfs(self, path: Path) -> str | None:
        """Read a sysfs/procfs attribute file. Returns the stripped string
        or None if unreadable. Doesn't raise on permission errors."""
        try:
            return path.read_text(encoding="utf-8", errors="replace").strip()
        except (OSError, UnicodeError):
            return None

    def read_plist(self, path: Path) -> dict[str, Any] | None:
        """Parse a binary/XML plist; None if unreadable or not a dict."""
        try:
            with open(path, "rb") as stream:
                parsed = plistlib.load(stream)
        except (OSError, plistlib.InvalidFileException, ValueError, ExpatError):
            return None
        return parsed if isinstance(parsed, dict) else None

    def _container_homes(self) -> list[Path]:
        homes = self._user_homes(self.under_prefix("home"))
        root_home = self.under_prefix("root")
        if root_home.is_dir():
            homes.append(root_home)
        return homes

    def _user_homes(self, home_root: Path) -> list[Path]:
        if not home_root.is_dir():
            return []
        try:
            return [user_dir for user_dir in home_root.iterdir() if user_dir.is_dir()]
        except OSError:
            return []
