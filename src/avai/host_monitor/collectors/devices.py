from __future__ import annotations

import configparser
import json
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

from ..slices import Slices
from ..runtime import Coerce, CommandRunner, HostIo, HostPaths
from .base import SnapshotCollector

PROFILER_TIMEOUT_S = 30
IW_TIMEOUT_S = 5


class SystemProfiler:
    """The sections ``system_profiler -json <DataType>`` reports."""

    def __init__(self, runner: CommandRunner, data_type: str) -> None:
        self._runner = runner
        self._data_type = data_type

    def sections(self) -> list[Any]:
        report = self._runner.json(
            ["system_profiler", "-json", self._data_type], timeout=PROFILER_TIMEOUT_S
        )
        if isinstance(report, dict):
            return report.get(self._data_type, [])
        return report or []


class UsbDevicesCollector(SnapshotCollector):
    slice = Slices.USB_DEVICES
    judge_fields = ("name", "vendor_id", "product_id", "manufacturer")

    def __init__(self, runner: CommandRunner, judge_hints: str = "") -> None:
        super().__init__(judge_hints)
        self._runner = runner

    def collect(self) -> Iterator[dict[str, Any]]:
        yield from self._walk(
            SystemProfiler(self._runner, "SPUSBDataType").sections(), None
        )

    def _walk(
        self, items: Iterable[Mapping[str, Any]] | None, parent_location: str | None
    ) -> Iterator[dict[str, Any]]:
        for item in items or []:
            location = item.get("location_id") or parent_location
            details = {key: value for key, value in item.items() if key != "_items"}
            yield {
                "name": item.get("_name"),
                "vendor_id": item.get("vendor_id"),
                "product_id": item.get("product_id"),
                "serial_number": item.get("serial_num"),
                "manufacturer": item.get("manufacturer"),
                "location_id": location,
                "speed": item.get("device_speed"),
                "raw_json": json.dumps(Coerce().jsonable(details)),
            }
            yield from self._walk(item.get("_items"), location)


class BluetoothCollector(SnapshotCollector):
    slice = Slices.BLUETOOTH_DEVICES
    judge_fields = ("name", "address", "minor_type")
    GROUPS = (
        "device_connected",
        "device_not_connected",
        "device_paired",
        "devices_list",
    )
    PAIRED_GROUPS = frozenset(
        {"device_connected", "device_not_connected", "device_paired"}
    )

    def __init__(self, runner: CommandRunner, judge_hints: str = "") -> None:
        super().__init__(judge_hints)
        self._runner = runner

    def collect(self) -> Iterator[dict[str, Any]]:
        for section in SystemProfiler(self._runner, "SPBluetoothDataType").sections():
            for group in self.GROUPS:
                yield from self._group_rows(group, section.get(group, []) or [])

    def _group_rows(self, group: str, entries: list[Any]) -> Iterator[dict[str, Any]]:
        devices = (
            (device_name, device)
            for entry in entries
            if isinstance(entry, dict)
            for device_name, device in entry.items()
            if isinstance(device, dict)
        )
        for device_name, device in devices:
            yield {
                "name": device_name,
                "address": device.get("device_address"),
                "connected": int(group == "device_connected"),
                "paired": int(group in self.PAIRED_GROUPS),
                "minor_type": device.get("device_minorType"),
                "raw_json": json.dumps(Coerce().jsonable(device)),
            }


class WifiCollector(SnapshotCollector):
    slice = Slices.WIFI_STATE
    judge_fields = ("ssid", "bssid", "security")

    def __init__(self, runner: CommandRunner, judge_hints: str = "") -> None:
        super().__init__(judge_hints)
        self._runner = runner

    def collect(self) -> Iterator[dict[str, Any]]:
        interfaces = (
            iface
            for entry in SystemProfiler(self._runner, "SPAirPortDataType").sections()
            for iface in entry.get("spairport_airport_interfaces", []) or []
        )
        for iface in interfaces:
            network = iface.get("spairport_current_network_information") or {}
            channel = network.get("spairport_network_channel")
            yield {
                "interface": iface.get("_name"),
                "ssid": network.get("_name"),
                "bssid": network.get("spairport_network_bssid"),
                "channel": str(channel) if channel is not None else None,
                "security": network.get("spairport_security_mode"),
                "raw_json": json.dumps(Coerce().jsonable(network)),
            }


class SysfsDirectory:
    """The sub-directories of one sysfs/host directory, sorted by name;
    empty when the directory is missing or unreadable."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def children(self) -> list[Path]:
        if not self._path.is_dir():
            return []
        try:
            entries = sorted(self._path.iterdir(), key=lambda entry: entry.name)
        except OSError:
            return []
        return [entry for entry in entries if entry.is_dir()]


class LinuxUsbDevicesCollector(SnapshotCollector):
    """Linux equivalent of :class:`UsbDevicesCollector`.

    Walks ``/sys/bus/usb/devices`` and reads attribute files (kernel
    exposes the USB descriptors as plain-text files — no parsing
    needed, just :func:`Path.read_text`). Interface sub-nodes (those
    with a ``:`` in their name like ``1-1:1.0``) are skipped — we
    only want device-level entries.
    """

    slice = Slices.USB_DEVICES
    judge_fields = ("name", "vendor_id", "product_id", "manufacturer")

    ATTRS = (
        "idVendor",
        "idProduct",
        "manufacturer",
        "product",
        "serial",
        "speed",
        "bDeviceClass",
        "bDeviceProtocol",
        "bMaxPower",
        "version",
        "busnum",
        "devnum",
    )

    def __init__(self, paths: HostPaths, judge_hints: str = "") -> None:
        super().__init__(judge_hints)
        self._paths = paths

    def collect(self) -> Iterator[dict[str, Any]]:
        root = self._paths.translate("/sys/bus/usb/devices")
        # USB device nodes are named like "1-1", "2-1.2", "usb1". Interfaces
        # (which carry a colon) are sub-descriptors of devices — skip them.
        devices = [
            dev for dev in SysfsDirectory(root).children() if ":" not in dev.name
        ]
        for device in devices:
            attrs = self._attrs(device)
            # Skip empty entries (e.g. root hubs without descriptors).
            if attrs.get("idVendor") or attrs.get("product"):
                yield self._row(device.name, attrs)

    def _attrs(self, device: Path) -> dict[str, str]:
        read = {attr: self._paths.read_sysfs(device / attr) for attr in self.ATTRS}
        return {attr: value for attr, value in read.items() if value is not None}

    def _row(self, location: str, attrs: Mapping[str, str]) -> dict[str, Any]:
        return {
            "name": attrs.get("product"),
            "vendor_id": attrs.get("idVendor"),
            "product_id": attrs.get("idProduct"),
            "serial_number": attrs.get("serial"),
            "manufacturer": attrs.get("manufacturer"),
            "location_id": location,
            "speed": attrs.get("speed"),
            "raw_json": json.dumps(attrs),
        }


class BluezDevice:
    """One paired device under ``/var/lib/bluetooth/<adapter>/<device>``,
    read from its INI ``info`` file."""

    def __init__(self, directory: Path) -> None:
        self._directory = directory

    def row(self) -> dict[str, Any] | None:
        parser = self._read()
        if parser is None:
            return None
        general = dict(parser["General"]) if parser.has_section("General") else {}
        return {
            "name": general.get("Alias") or general.get("Name"),
            # BlueZ stores the MAC with underscores; restore colons.
            "address": self._directory.name.replace("_", ":"),
            "connected": 0,
            "paired": 1,
            "minor_type": general.get("Class"),
            "raw_json": json.dumps(
                {section: dict(parser[section]) for section in parser.sections()}
            ),
        }

    def _read(self) -> configparser.ConfigParser | None:
        info_file = self._directory / "info"
        if not info_file.is_file():
            return None
        parser = configparser.ConfigParser(
            interpolation=None, strict=False, inline_comment_prefixes=("#", ";")
        )
        # BlueZ info keys are CamelCase (Alias, Name, Class). Preserve case —
        # default lowercasing blanked the device name + class.
        parser.optionxform = str
        try:
            parser.read(info_file, encoding="utf-8")
        except (configparser.Error, OSError):
            return None
        return parser


class LinuxBluetoothCollector(SnapshotCollector):
    """Linux equivalent of :class:`BluetoothCollector`.

    Walks ``/var/lib/bluetooth/<adapter_mac>/<device_mac>/info`` — the
    persistent state files BlueZ writes for every paired device. Each
    file is an INI document parsed by :mod:`configparser`. Presence
    in this directory means the device is paired; live connectivity
    requires D-Bus (deferred to a future phase) so ``connected`` is
    left as 0.

    Requires read access to ``/var/lib/bluetooth`` which is normally
    root-only — the monitor container runs as root.
    """

    slice = Slices.BLUETOOTH_DEVICES
    judge_fields = ("name", "address", "minor_type")

    def __init__(self, paths: HostPaths, judge_hints: str = "") -> None:
        super().__init__(judge_hints)
        self._paths = paths

    def collect(self) -> Iterator[dict[str, Any]]:
        root = self._paths.translate("/var/lib/bluetooth")
        devices = (
            device
            for adapter in SysfsDirectory(root).children()
            for device in SysfsDirectory(adapter).children()
        )
        for device in devices:
            row = BluezDevice(device).row()
            if row is not None:
                yield row


class IwLink:
    """``iw dev <iface> link`` output parsed line by line (``key: value``)."""

    def __init__(self, text: str) -> None:
        self._text = text

    def fields(self) -> dict[str, str]:
        parsed: dict[str, str] = {}
        for raw in self._text.splitlines():
            parsed.update(self._line_fields(raw.strip()))
        return parsed

    def _line_fields(self, line: str) -> dict[str, str]:
        if line.startswith("Connected to"):
            bssid = line.removeprefix("Connected to").split()
            return {"BSSID": bssid[0]} if bssid else {}
        if line.startswith("Not connected"):
            return {"connected": "no"}
        key, sep, value = line.partition(":")
        return {key.strip(): value.strip()} if sep else {}


class LinuxWifiCollector(SnapshotCollector):
    """Linux equivalent of :class:`WifiCollector`.

    Discovers wireless interfaces from sysfs (any net interface that
    has a ``wireless/`` subdirectory in ``/sys/class/net``). For each,
    asks ``iw dev <iface> link`` for the current connection details
    (SSID, BSSID, freq) — parsed line-by-line using ``key: value``
    structure, not regex. If ``iw`` isn't installed the interface is
    still emitted with empty fields so the dashboard can see it
    exists.
    """

    slice = Slices.WIFI_STATE
    judge_fields = ("ssid", "bssid", "security")

    def __init__(self, io: HostIo, judge_hints: str = "") -> None:
        super().__init__(judge_hints)
        self._io = io

    def collect(self) -> Iterator[dict[str, Any]]:
        # sysfs discovery via HOST_PREFIX; iw queries via netlink which the
        # host-network namespace (network_mode: host) already exposes to the
        # container.
        net = self._io.paths.translate("/sys/class/net")
        interfaces = SysfsDirectory(net).children()
        wireless = [iface for iface in interfaces if (iface / "wireless").is_dir()]
        iw_available = self._io.runner.exists("iw")
        for iface_dir in wireless:
            link = self._link(iface_dir.name) if iw_available else {}
            yield {
                "interface": iface_dir.name,
                "ssid": link.get("SSID"),
                "bssid": link.get("BSSID"),
                "channel": link.get("freq"),
                "security": link.get("type"),
                "raw_json": json.dumps(link),
            }

    def _link(self, iface: str) -> dict[str, str]:
        text = self._io.runner.text(["iw", "dev", iface, "link"], timeout=IW_TIMEOUT_S)
        return IwLink(text).fields()
