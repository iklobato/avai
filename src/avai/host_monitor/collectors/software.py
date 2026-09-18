"""Installed software: apps and packages, browser extensions, downloads,
profiles and extensions."""

from __future__ import annotations

import configparser
import json
import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable, Optional

from .. import constants, slices
from ..constants import (
    APP_INFO_KEYS,
    BROWSER_PROFILES,
)
from ..enums import Browser
from ..runtime import (
    Coerce,
    CommandRunner,
    ExternalSqliteReader,
    HostPaths,
)
from .base import SnapshotCollector


class BrowserExtensionReader(ABC):
    @abstractmethod
    def read(self, base: Path, browser: Browser) -> Iterable[dict]: ...


class ChromiumExtensionReader(BrowserExtensionReader):
    def read(self, base, browser):
        try:
            profile_dirs = list(base.iterdir())
        except OSError:
            return
        for profile_dir in profile_dirs:
            ext_root = profile_dir / "Extensions"
            if not ext_root.is_dir():
                continue
            for ext_id_dir in ext_root.iterdir():
                if not ext_id_dir.is_dir():
                    continue
                for version_dir in ext_id_dir.iterdir():
                    manifest = version_dir / "manifest.json"
                    if not manifest.is_file():
                        continue
                    try:
                        m = json.loads(
                            manifest.read_text(encoding="utf-8", errors="replace")
                        )
                    except (json.JSONDecodeError, OSError):
                        continue
                    yield {
                        "browser": str(browser),
                        "profile": profile_dir.name,
                        "extension_id": ext_id_dir.name,
                        "name": m.get("name"),
                        "version": m.get("version"),
                        "permissions_json": json.dumps(m.get("permissions") or []),
                        "host_permissions_json": json.dumps(
                            m.get("host_permissions") or m.get("matches") or []
                        ),
                        "path": str(version_dir),
                        "manifest_json": json.dumps(m),
                    }


class FirefoxExtensionReader(BrowserExtensionReader):
    def read(self, base, browser):
        profiles_dir = base / "Profiles"
        if not profiles_dir.is_dir():
            return
        for profile_dir in profiles_dir.iterdir():
            ext_file = profile_dir / "extensions.json"
            if not ext_file.is_file():
                continue
            try:
                data = json.loads(
                    ext_file.read_text(encoding="utf-8", errors="replace")
                )
            except (json.JSONDecodeError, OSError):
                continue
            for addon in data.get("addons", []) or []:
                up = addon.get("userPermissions") or {}
                dl = addon.get("defaultLocale") or {}
                yield {
                    "browser": str(browser),
                    "profile": profile_dir.name,
                    "extension_id": addon.get("id"),
                    "name": dl.get("name"),
                    "version": addon.get("version"),
                    "permissions_json": json.dumps(up.get("permissions") or []),
                    "host_permissions_json": json.dumps(up.get("origins") or []),
                    "path": addon.get("path"),
                    "manifest_json": json.dumps(addon),
                }


class QuarantineCollector(SnapshotCollector):
    slice = slices.QUARANTINE_EVENTS
    judge_fields = ("agent_bundle_id", "agent_name", "origin_url", "data_url")
    _COLUMN_MAP = {
        "LSQuarantineEventIdentifier": "event_id",
        "LSQuarantineTimeStamp": "timestamp",
        "LSQuarantineAgentBundleIdentifier": "agent_bundle_id",
        "LSQuarantineAgentName": "agent_name",
        "LSQuarantineOriginURLString": "origin_url",
        "LSQuarantineDataURLString": "data_url",
        "LSQuarantineSenderName": "sender_name",
        "LSQuarantineTypeNumber": "type_number",
    }

    def collect(self):
        path = HostPaths.expand(
            "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
        )
        if not path.exists():
            return
        for row in ExternalSqliteReader().rows(
            path, "LSQuarantineEvent", list(self._COLUMN_MAP.keys())
        ):
            yield {self._COLUMN_MAP[k]: v for k, v in row.items()}


class BrowserExtensionsCollector(SnapshotCollector):
    slice = slices.BROWSER_EXTENSIONS
    judge_fields = (
        "browser",
        "extension_id",
        "name",
        "permissions_json",
        "host_permissions_json",
    )

    def __init__(
        self,
        readers: Optional[dict[Browser, BrowserExtensionReader]] = None,
        default_reader: Optional[BrowserExtensionReader] = None,
        judge_hints: str = "",
        profiles: Optional[dict[Browser, list[str]]] = None,
    ):
        super().__init__(judge_hints=judge_hints)
        self.readers = readers or {Browser.FIREFOX: FirefoxExtensionReader()}
        self.default_reader = default_reader or ChromiumExtensionReader()
        # Per-platform search roots — caller supplies BROWSER_PROFILES
        # or BROWSER_PROFILES_LINUX. Defaults to the macOS layout.
        self.profiles = profiles or BROWSER_PROFILES

    def collect(self):
        for browser, profiles in self.profiles.items():
            reader = self.readers.get(browser, self.default_reader)
            for base_str in profiles:
                base = HostPaths.expand(base_str)
                if not base.is_dir():
                    continue
                yield from reader.read(base, browser)


class InstalledAppsCollector(SnapshotCollector):
    slice = slices.INSTALLED_APPS
    judge_fields = ("bundle_id", "name", "path")

    def collect(self):
        for app_dir in (Path("/Applications"), HostPaths.expand("~/Applications")):
            if not app_dir.is_dir():
                continue
            try:
                apps = list(app_dir.glob("*.app"))
            except PermissionError:
                continue
            for app in apps:
                info = HostPaths.read_plist(app / "Contents" / "Info.plist") or {}
                yield {
                    "path": str(app),
                    "bundle_id": info.get("CFBundleIdentifier"),
                    "name": info.get("CFBundleName") or info.get("CFBundleDisplayName"),
                    "version": info.get("CFBundleShortVersionString"),
                    "raw_json": json.dumps(
                        Coerce.jsonable(
                            {
                                k: info.get(k)
                                for k in APP_INFO_KEYS
                                if info.get(k) is not None
                            }
                        )
                    ),
                }


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

    slice = slices.INSTALLED_APPS
    judge_fields = ("bundle_id", "name", "path")

    _DPKG_FIELDS = ("Status", "Package", "Version", "Architecture", "Description")

    def collect(self):
        yield from self._dpkg_rows()
        yield from self._desktop_rows()

    def _dpkg_rows(self):
        if not shutil.which("dpkg-query"):
            return
        # Tab-separated fixed-field output: no parsing of dpkg -l's
        # column-aligned text. dpkg-query -W -f gives us structured
        # output with a chosen delimiter.
        fmt = (
            "${db:Status-Status}\t${Package}\t${Version}\t"
            "${Architecture}\t${binary:Summary}\n"
        )
        cmd = ["dpkg-query", "-W", "-f", fmt]
        # When containerised, --admindir points dpkg-query at the host's
        # package database rather than the container's.
        host_admindir = HostPaths.translate("/var/lib/dpkg")
        if constants.HOST_PREFIX and host_admindir.is_dir():
            cmd[1:1] = ["--admindir", str(host_admindir)]
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return
        if r.returncode != 0:
            return
        for line in r.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            status, name, version, arch, summary = (
                parts[0],
                parts[1],
                parts[2],
                parts[3],
                parts[4],
            )
            if status != "installed":
                continue
            yield {
                "path": f"dpkg:{name}",
                "bundle_id": name,
                "name": name,
                "version": version,
                "raw_json": json.dumps(
                    {
                        "source": "dpkg",
                        "status": status,
                        "architecture": arch,
                        "summary": summary,
                    }
                ),
            }

    def _desktop_rows(self):
        # XDG desktop entries are simple INI files; configparser
        # handles them. We extract [Desktop Entry] Name / Exec /
        # Comment / Categories.
        roots: list[Path] = [
            HostPaths.translate("/usr/share/applications"),
            HostPaths.translate("/usr/local/share/applications"),
            HostPaths.translate("/var/lib/flatpak/exports/share/applications"),
        ]
        roots.extend(HostPaths.for_home("~/.local/share/applications"))
        roots.extend(
            HostPaths.for_home("~/.local/share/flatpak/exports/share/applications")
        )
        for root in roots:
            if not root.is_dir():
                continue
            try:
                entries = list(root.glob("*.desktop"))
            except PermissionError:
                continue
            for entry in entries:
                cp = configparser.ConfigParser(
                    interpolation=None,
                    strict=False,
                )
                # .desktop keys are CamelCase (Name, Exec, Version,
                # Type). Preserve case — the default lowercasing made
                # every sec.get("Name")/("Exec") miss.
                cp.optionxform = str
                try:
                    cp.read(entry, encoding="utf-8")
                except (configparser.Error, OSError):
                    continue
                if "Desktop Entry" not in cp:
                    continue
                sec = cp["Desktop Entry"]
                yield {
                    "path": str(entry),
                    "bundle_id": entry.stem,
                    "name": sec.get("Name"),
                    "version": sec.get("Version"),
                    "raw_json": json.dumps(
                        {
                            "source": "desktop",
                            "exec": sec.get("Exec"),
                            "comment": sec.get("Comment"),
                            "categories": sec.get("Categories"),
                            "type": sec.get("Type"),
                            "no_display": sec.get("NoDisplay") == "true",
                        }
                    ),
                }


class MdmProfilesCollector(SnapshotCollector):
    """macOS configuration profiles (MDM payloads). Unauthorized MDM
    enrollment is a major compromise vector — a malicious profile
    can install root CAs, push launch agents, configure VPNs, or
    restrict settings system-wide. ``system_profiler
    SPConfigurationProfileDataType`` gives us a structured (JSON)
    view of every installed profile."""

    slice = slices.MDM_PROFILES
    judge_fields = ("identifier", "display_name", "organization", "profile_scope")

    def collect(self):
        try:
            data = CommandRunner().json(
                ["system_profiler", "-json", "SPConfigurationProfileDataType"],
                timeout=30,
            )
        except (RuntimeError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        profiles = data.get("SPConfigurationProfileDataType", []) or []
        # The output structure is "list of nested groups, with profile
        # records under either _items or directly at the top level."
        for entry in self._walk(profiles):
            yield {
                "identifier": entry.get("spconfigprofile_profile_identifier"),
                "display_name": entry.get("_name")
                or entry.get("spconfigprofile_profile_display_name"),
                "organization": entry.get("spconfigprofile_profile_organization"),
                "description": entry.get("spconfigprofile_profile_description"),
                "install_date": entry.get("spconfigprofile_install_date"),
                "profile_scope": entry.get("spconfigprofile_profile_scope"),
                "is_supervised": None,
                "raw_json": json.dumps(Coerce.jsonable(entry)),
            }

    @classmethod
    def _walk(cls, items):
        for item in items or []:
            if not isinstance(item, dict):
                continue
            # A node is a profile if it has an identifier field, else
            # descend into _items.
            if item.get("spconfigprofile_profile_identifier"):
                yield item
            if "_items" in item:
                yield from cls._walk(item.get("_items"))


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

    slice = slices.KERNEL_EXTENSIONS
    judge_fields = ("bundle_id", "name", "team_id")

    def collect(self):
        try:
            data = CommandRunner().json(
                ["system_profiler", "-json", "SPExtensionsDataType"],
                timeout=60,
            )
        except (RuntimeError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        for kext in data.get("SPExtensionsDataType", []) or []:
            if not isinstance(kext, dict):
                continue
            yield {
                "bundle_id": kext.get("spext_bundleid"),
                "name": kext.get("_name"),
                "version": kext.get("spext_version"),
                "path": kext.get("spext_path"),
                "team_id": None,
                "signing_id": kext.get("spext_signed_by"),
                "raw_json": json.dumps(
                    Coerce.jsonable(
                        {
                            k: v
                            for k, v in kext.items()
                            if k
                            in (
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
                            )
                        }
                    )
                ),
            }


class SystemExtensionsCollector(SnapshotCollector):
    """macOS System Extensions — the post-Catalina replacement for
    kexts. Used by network filters (NEFilter), DriverKit
    (USB/serial), and endpoint-security extensions (ES).

    Source: ``/Library/SystemExtensions/db.plist`` — the LaunchServices
    plist that records every installed extension and its enabled /
    active state. Parsed via :mod:`plistlib`; no text scraping of
    ``systemextensionsctl list`` output.
    """

    slice = slices.SYSTEM_EXTENSIONS
    judge_fields = ("bundle_id", "team_id")

    def collect(self):
        db = Path("/Library/SystemExtensions/db.plist")
        data = HostPaths.read_plist(db)
        if not data:
            return
        # The plist is a top-level dict with 'extensions' as the list
        # of every installed System Extension (one entry per ext,
        # regardless of activation state). 'bundleVersion' is a
        # nested dict carrying both CFBundleShortVersionString and
        # CFBundleVersion. 'categories' is a list of extension-point
        # identifiers (network_extension, endpoint_security, …).
        for ext in data.get("extensions", []) or []:
            if not isinstance(ext, dict):
                continue
            version = ext.get("bundleVersion")
            if isinstance(version, dict):
                version = version.get("CFBundleShortVersionString") or version.get(
                    "CFBundleVersion"
                )
            categories = ext.get("categories") or []
            yield {
                "bundle_id": ext.get("identifier"),
                "team_id": ext.get("teamID"),
                "version": version,
                "state": ext.get("state"),
                "categories": ",".join(categories) if categories else None,
                "raw_json": json.dumps(Coerce.jsonable(ext)),
            }
