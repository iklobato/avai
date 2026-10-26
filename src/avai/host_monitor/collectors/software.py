from __future__ import annotations

import configparser
import json
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import constants
from ..slices import Slices
from ..constants import APP_INFO_KEYS
from ..enums import Browser
from ..runtime import Coerce, CommandRunner, ExternalSqliteReader, HostPaths
from .base import SnapshotCollector

PROFILER_TIMEOUT_S = 30
KEXT_PROFILER_TIMEOUT_S = 60
DPKG_TIMEOUT_S = 30
DPKG_FIELDS = ("Status", "Package", "Version", "Architecture", "Description")
DPKG_FORMAT = (
    "${db:Status-Status}\t${Package}\t${Version}\t${Architecture}\t${binary:Summary}\n"
)
DESKTOP_ROOTS = (
    "/usr/share/applications",
    "/usr/local/share/applications",
    "/var/lib/flatpak/exports/share/applications",
)
DESKTOP_HOME_ROOTS = (
    "~/.local/share/applications",
    "~/.local/share/flatpak/exports/share/applications",
)
DESKTOP_SECTION = "Desktop Entry"
KEXT_DETAIL_KEYS = frozenset(
    {
        "_name",
        "spext_bundleid",
        "spext_version",
        "spext_path",
        "spext_signed_by",
        "spext_obtained_from",
        "spext_notarized",
        "spext_loaded",
        "spext_loadable",
        "spext_lastModified",
        "spext_hasAllDependencies",
    }
)
PROFILE_ID_KEY = "spconfigprofile_profile_identifier"


class JsonFile:
    """A JSON document on disk; None when unreadable or malformed."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> Any | None:
        try:
            return json.loads(self._path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            return None


class ProfilerReport:
    """The entries of one ``system_profiler -json <DataType>`` report; []
    when the tool fails or prints something unexpected."""

    def __init__(self, runner: CommandRunner, data_type: str) -> None:
        self._runner = runner
        self._data_type = data_type

    def entries(self, timeout: int) -> list[Any]:
        command = ["system_profiler", "-json", self._data_type]
        try:
            report = self._runner.json(command, timeout=timeout)
        except (RuntimeError, json.JSONDecodeError):
            return []
        if not isinstance(report, dict):
            return []
        return report.get(self._data_type, []) or []


class BrowserExtensionReader(ABC):
    @abstractmethod
    def read(self, base: Path, browser: Browser) -> Iterable[dict[str, Any]]: ...


class ChromiumExtensionReader(BrowserExtensionReader):
    def read(self, base: Path, browser: Browser) -> Iterator[dict[str, Any]]:
        try:
            profile_dirs = list(base.iterdir())
        except OSError:
            return
        rows = (
            self._row(browser, profile_dir, version_dir)
            for profile_dir in profile_dirs
            for version_dir in self._version_dirs(profile_dir / "Extensions")
        )
        yield from (row for row in rows if row is not None)

    def _version_dirs(self, ext_root: Path) -> list[Path]:
        if not ext_root.is_dir():
            return []
        return [
            version_dir
            for ext_id_dir in ext_root.iterdir()
            if ext_id_dir.is_dir()
            for version_dir in ext_id_dir.iterdir()
        ]

    def _row(
        self, browser: Browser, profile_dir: Path, version_dir: Path
    ) -> dict[str, Any] | None:
        manifest_path = version_dir / "manifest.json"
        manifest = JsonFile(manifest_path).load() if manifest_path.is_file() else None
        if manifest is None:
            return None
        return {
            "browser": str(browser),
            "profile": profile_dir.name,
            "extension_id": version_dir.parent.name,
            "name": manifest.get("name"),
            "version": manifest.get("version"),
            "permissions_json": json.dumps(manifest.get("permissions") or []),
            "host_permissions_json": json.dumps(
                manifest.get("host_permissions") or manifest.get("matches") or []
            ),
            "path": str(version_dir),
            "manifest_json": json.dumps(manifest),
        }


class FirefoxExtensionReader(BrowserExtensionReader):
    def read(self, base: Path, browser: Browser) -> Iterator[dict[str, Any]]:
        profiles_dir = base / "Profiles"
        if not profiles_dir.is_dir():
            return
        for profile_dir in profiles_dir.iterdir():
            ext_file = profile_dir / "extensions.json"
            extensions = JsonFile(ext_file).load() if ext_file.is_file() else None
            if extensions is None:
                continue
            for addon in extensions.get("addons", []) or []:
                yield self._row(browser, profile_dir.name, addon)

    def _row(
        self, browser: Browser, profile: str, addon: Mapping[str, Any]
    ) -> dict[str, Any]:
        permissions = addon.get("userPermissions") or {}
        return {
            "browser": str(browser),
            "profile": profile,
            "extension_id": addon.get("id"),
            "name": (addon.get("defaultLocale") or {}).get("name"),
            "version": addon.get("version"),
            "permissions_json": json.dumps(permissions.get("permissions") or []),
            "host_permissions_json": json.dumps(permissions.get("origins") or []),
            "path": addon.get("path"),
            "manifest_json": json.dumps(addon),
        }


class QuarantineCollector(SnapshotCollector):
    slice = Slices.QUARANTINE_EVENTS
    judge_fields = ("agent_bundle_id", "agent_name", "origin_url", "data_url")
    COLUMN_MAP = (
        ("LSQuarantineEventIdentifier", "event_id"),
        ("LSQuarantineTimeStamp", "timestamp"),
        ("LSQuarantineAgentBundleIdentifier", "agent_bundle_id"),
        ("LSQuarantineAgentName", "agent_name"),
        ("LSQuarantineOriginURLString", "origin_url"),
        ("LSQuarantineDataURLString", "data_url"),
        ("LSQuarantineSenderName", "sender_name"),
        ("LSQuarantineTypeNumber", "type_number"),
    )

    def collect(self) -> Iterator[dict[str, Any]]:
        path = HostPaths().expand(
            "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
        )
        if not path.exists():
            return
        columns = dict(self.COLUMN_MAP)
        rows = ExternalSqliteReader().rows(path, "LSQuarantineEvent", list(columns))
        for row in rows:
            yield {columns[key]: value for key, value in row.items()}


@dataclass(frozen=True)
class ExtensionReaders:
    """The reader for each browser family; ``default`` reads the rest."""

    default: BrowserExtensionReader
    by_browser: Mapping[Browser, BrowserExtensionReader] = field(default_factory=dict)

    @classmethod
    def standard(cls) -> ExtensionReaders:
        return cls(
            ChromiumExtensionReader(), {Browser.FIREFOX: FirefoxExtensionReader()}
        )

    def for_browser(self, browser: Browser) -> BrowserExtensionReader:
        return self.by_browser.get(browser, self.default)


class BrowserExtensionsCollector(SnapshotCollector):
    slice = Slices.BROWSER_EXTENSIONS
    judge_fields = (
        "browser",
        "extension_id",
        "name",
        "permissions_json",
        "host_permissions_json",
    )

    def __init__(
        self,
        readers: ExtensionReaders,
        profiles: Mapping[Browser, Iterable[str]],
        judge_hints: str = "",
    ) -> None:
        super().__init__(judge_hints=judge_hints)
        self._readers = readers
        # Per-platform search roots — the host supplies BROWSER_PROFILES or
        # BROWSER_PROFILES_LINUX.
        self._profiles = profiles

    @classmethod
    def create(
        cls, profiles: Mapping[Browser, Iterable[str]], judge_hints: str = ""
    ) -> BrowserExtensionsCollector:
        return cls(ExtensionReaders.standard(), profiles, judge_hints)

    def collect(self) -> Iterator[dict[str, Any]]:
        paths = HostPaths()
        for browser, profiles in self._profiles.items():
            reader = self._readers.for_browser(browser)
            bases = [paths.expand(base_str) for base_str in profiles]
            for base in (base for base in bases if base.is_dir()):
                yield from reader.read(base, browser)


class InstalledAppsCollector(SnapshotCollector):
    slice = Slices.INSTALLED_APPS
    judge_fields = ("bundle_id", "name", "path")

    def collect(self) -> Iterator[dict[str, Any]]:
        app_dirs = (Path("/Applications"), HostPaths().expand("~/Applications"))
        for app in (app for app_dir in app_dirs for app in self._apps(app_dir)):
            bundle = HostPaths().read_plist(app / "Contents" / "Info.plist") or {}
            details = {key: bundle.get(key) for key in APP_INFO_KEYS}
            yield {
                "path": str(app),
                "bundle_id": bundle.get("CFBundleIdentifier"),
                "name": bundle.get("CFBundleName") or bundle.get("CFBundleDisplayName"),
                "version": bundle.get("CFBundleShortVersionString"),
                "raw_json": json.dumps(
                    Coerce().jsonable(
                        {
                            key: value
                            for key, value in details.items()
                            if value is not None
                        }
                    )
                ),
            }

    def _apps(self, app_dir: Path) -> list[Path]:
        if not app_dir.is_dir():
            return []
        try:
            return list(app_dir.glob("*.app"))
        except PermissionError:
            return []


class DpkgPackages:
    """Installed Debian packages, from ``dpkg-query``'s tab-separated output
    (no parsing of dpkg -l's column-aligned text)."""

    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner

    def rows(self) -> Iterator[dict[str, Any]]:
        if not self._runner.exists("dpkg-query"):
            return
        output = self._runner.text(self._command(), timeout=DPKG_TIMEOUT_S)
        fields = (line.split("\t") for line in output.splitlines())
        for parts in (parts for parts in fields if len(parts) >= len(DPKG_FIELDS)):
            if parts[0] == "installed":
                yield self._row(parts)

    def _row(self, parts: list[str]) -> dict[str, Any]:
        status, name, version, arch, summary, *_rest = parts
        details = {"status": status, "architecture": arch, "summary": summary}
        return {
            "path": f"dpkg:{name}",
            "bundle_id": name,
            "name": name,
            "version": version,
            "raw_json": json.dumps({"source": "dpkg", **details}),
        }

    def _command(self) -> list[str]:
        # When containerised, --admindir points dpkg-query at the host's
        # package database rather than the container's.
        host_admindir = HostPaths().translate("/var/lib/dpkg")
        admindir = (
            ["--admindir", str(host_admindir)]
            if constants.HOST_PREFIX and host_admindir.is_dir()
            else []
        )
        return ["dpkg-query", *admindir, "-W", "-f", DPKG_FORMAT]


class DesktopEntry:
    """One XDG ``.desktop`` file (a simple INI document) as an app row."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def row(self) -> dict[str, Any] | None:
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        # .desktop keys are CamelCase (Name, Exec, Version, Type). Preserve
        # case — the default lowercasing made every lookup miss.
        parser.optionxform = str
        try:
            parser.read(self._path, encoding="utf-8")
        except (configparser.Error, OSError):
            return None
        if DESKTOP_SECTION not in parser:
            return None
        return self._from_section(parser[DESKTOP_SECTION])

    def _from_section(self, section: Mapping[str, str]) -> dict[str, Any]:
        return {
            "path": str(self._path),
            "bundle_id": self._path.stem,
            "name": section.get("Name"),
            "version": section.get("Version"),
            "raw_json": json.dumps(
                {
                    "source": "desktop",
                    "exec": section.get("Exec"),
                    "comment": section.get("Comment"),
                    "categories": section.get("Categories"),
                    "type": section.get("Type"),
                    "no_display": section.get("NoDisplay") == "true",
                }
            ),
        }


class DesktopEntries:
    """GUI app menu entries from the system and per-user XDG directories."""

    def rows(self) -> Iterator[dict[str, Any]]:
        paths = HostPaths()
        roots = [paths.translate(root) for root in DESKTOP_ROOTS]
        roots += [
            home for template in DESKTOP_HOME_ROOTS for home in paths.for_home(template)
        ]
        for entry in (entry for root in roots for entry in self._entries(root)):
            row = DesktopEntry(entry).row()
            if row is not None:
                yield row

    def _entries(self, root: Path) -> list[Path]:
        if not root.is_dir():
            return []
        try:
            return list(root.glob("*.desktop"))
        except PermissionError:
            return []


class LinuxInstalledAppsCollector(SnapshotCollector):
    """Linux equivalent of :class:`InstalledAppsCollector`. Sources:

    - ``dpkg -l`` (Debian / Ubuntu / derivatives): installed binary
      packages. Each yields one row tagged ``source='dpkg'``.
    - ``/usr/share/applications/*.desktop`` (XDG, universal): GUI app
      menu entries. Each yields one row tagged ``source='desktop'``.

    The ``bundle_id`` column holds the package name (dpkg) or the
    ``.desktop`` filename's stem (XDG), so the judge dedupes via a
    stable identifier in either case.
    """

    slice = Slices.INSTALLED_APPS
    judge_fields = ("bundle_id", "name", "path")

    def __init__(self, runner: CommandRunner, judge_hints: str = "") -> None:
        super().__init__(judge_hints)
        self._runner = runner

    def collect(self) -> Iterator[dict[str, Any]]:
        yield from DpkgPackages(self._runner).rows()
        yield from DesktopEntries().rows()


class MdmProfilesCollector(SnapshotCollector):
    """macOS configuration profiles (MDM payloads). Unauthorized MDM
    enrollment is a major compromise vector — a malicious profile
    can install root CAs, push launch agents, configure VPNs, or
    restrict settings system-wide. ``system_profiler
    SPConfigurationProfileDataType`` gives us a structured (JSON)
    view of every installed profile."""

    slice = Slices.MDM_PROFILES
    judge_fields = ("identifier", "display_name", "organization", "profile_scope")

    def __init__(self, runner: CommandRunner, judge_hints: str = "") -> None:
        super().__init__(judge_hints)
        self._runner = runner

    def collect(self) -> Iterator[dict[str, Any]]:
        report = ProfilerReport(self._runner, "SPConfigurationProfileDataType")
        for entry in self.profiles(report.entries(PROFILER_TIMEOUT_S)):
            yield {
                "identifier": entry.get(PROFILE_ID_KEY),
                "display_name": entry.get("_name")
                or entry.get("spconfigprofile_profile_display_name"),
                "organization": entry.get("spconfigprofile_profile_organization"),
                "description": entry.get("spconfigprofile_profile_description"),
                "install_date": entry.get("spconfigprofile_install_date"),
                "profile_scope": entry.get("spconfigprofile_profile_scope"),
                "is_supervised": None,
                "raw_json": json.dumps(Coerce().jsonable(entry)),
            }

    def profiles(self, items: Iterable[Any] | None) -> Iterator[dict[str, Any]]:
        """The output is a list of nested groups, with profile records under
        either _items or directly at the top level: a node is a profile if
        it has an identifier field, and its _items are walked too."""
        for item in (item for item in items or [] if isinstance(item, dict)):
            if item.get(PROFILE_ID_KEY):
                yield item
            yield from self.profiles(item.get("_items"))


class KernelExtensionsCollector(SnapshotCollector):
    """macOS kernel extensions (kexts). Apple has deprecated them in
    favour of System Extensions, but third-party kexts can still
    load on older macOS or via legacy paths. Anything in ring 0 has
    full machine access — every loaded kext is high-signal.

    ``system_profiler -json SPExtensionsDataType`` is the structured
    source. It enumerates every installed kext (loaded or not),
    including the signing chain and notarisation state. The judge
    naturally ignores Apple-signed kexts and focuses on third-party
    ones via the prompt hints.
    """

    slice = Slices.KERNEL_EXTENSIONS
    judge_fields = ("bundle_id", "name", "team_id")

    def __init__(self, runner: CommandRunner, judge_hints: str = "") -> None:
        super().__init__(judge_hints)
        self._runner = runner

    def collect(self) -> Iterator[dict[str, Any]]:
        report = ProfilerReport(self._runner, "SPExtensionsDataType")
        kexts = report.entries(KEXT_PROFILER_TIMEOUT_S)
        for kext in (kext for kext in kexts if isinstance(kext, dict)):
            details = {
                key: value for key, value in kext.items() if key in KEXT_DETAIL_KEYS
            }
            yield {
                "bundle_id": kext.get("spext_bundleid"),
                "name": kext.get("_name"),
                "version": kext.get("spext_version"),
                "path": kext.get("spext_path"),
                "team_id": None,
                "signing_id": kext.get("spext_signed_by"),
                "raw_json": json.dumps(Coerce().jsonable(details)),
            }


class SystemExtensionsCollector(SnapshotCollector):
    """macOS System Extensions — the post-Catalina replacement for
    kexts. Used by network filters (NEFilter), DriverKit
    (USB/serial), and endpoint-security extensions (ES).

    Source: ``/Library/SystemExtensions/db.plist`` — the LaunchServices
    plist that records every installed extension and its enabled /
    active state. Parsed via :mod:`plistlib`; no text scraping of
    ``systemextensionsctl list`` output. The plist is a top-level dict
    with 'extensions' as the list of every installed System Extension
    (one entry per ext, regardless of activation state). 'bundleVersion'
    is a nested dict carrying both CFBundleShortVersionString and
    CFBundleVersion. 'categories' is a list of extension-point
    identifiers (network_extension, endpoint_security, …).
    """

    slice = Slices.SYSTEM_EXTENSIONS
    judge_fields = ("bundle_id", "team_id")

    def collect(self) -> Iterator[dict[str, Any]]:
        db = HostPaths().read_plist(Path("/Library/SystemExtensions/db.plist"))
        if not db:
            return
        extensions = db.get("extensions", []) or []
        for ext in (ext for ext in extensions if isinstance(ext, dict)):
            categories = ext.get("categories") or []
            yield {
                "bundle_id": ext.get("identifier"),
                "team_id": ext.get("teamID"),
                "version": self._version(ext.get("bundleVersion")),
                "state": ext.get("state"),
                "categories": ",".join(categories) if categories else None,
                "raw_json": json.dumps(Coerce().jsonable(ext)),
            }

    def _version(self, version: Any) -> Any:
        if isinstance(version, dict):
            return version.get("CFBundleShortVersionString") or version.get(
                "CFBundleVersion"
            )
        return version
