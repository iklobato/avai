"""Attached hardware: USB, Bluetooth and Wi-Fi, on macOS and Linux."""

from __future__ import annotations

import configparser
import json
import shutil
import subprocess

from .. import slices
from ..runtime import (
    Coerce,
    CommandRunner,
    HostPaths,
)
from .base import SnapshotCollector


class UsbDevicesCollector(SnapshotCollector):
    slice = slices.USB_DEVICES
    judge_fields = ("name", "vendor_id", "product_id", "manufacturer")

    def collect(self):
        data = CommandRunner().json(
            ["system_profiler", "-json", "SPUSBDataType"], timeout=30
        )
        root = data.get("SPUSBDataType", []) if isinstance(data, dict) else (data or [])
        yield from self._walk(root, None)

    def _walk(self, items, parent_location):
        for item in items or []:
            loc = item.get("location_id") or parent_location
            yield {
                "name": item.get("_name"),
                "vendor_id": item.get("vendor_id"),
                "product_id": item.get("product_id"),
                "serial_number": item.get("serial_num"),
                "manufacturer": item.get("manufacturer"),
                "location_id": loc,
                "speed": item.get("device_speed"),
                "raw_json": json.dumps(
                    {k: Coerce.jsonable(v) for k, v in item.items() if k != "_items"}
                ),
            }
            yield from self._walk(item.get("_items"), loc)


class BluetoothCollector(SnapshotCollector):
    slice = slices.BLUETOOTH_DEVICES
    judge_fields = ("name", "address", "minor_type")
    _GROUPS = (
        "device_connected",
        "device_not_connected",
        "device_paired",
        "devices_list",
    )
    _PAIRED_GROUPS = {"device_connected", "device_not_connected", "device_paired"}

    def collect(self):
        data = CommandRunner().json(
            ["system_profiler", "-json", "SPBluetoothDataType"], timeout=30
        )
        sections = (
            data.get("SPBluetoothDataType", [])
            if isinstance(data, dict)
            else (data or [])
        )
        for section in sections:
            for group in self._GROUPS:
                for entry in section.get(group, []) or []:
                    if not isinstance(entry, dict):
                        continue
                    for dev_name, dev in entry.items():
                        if not isinstance(dev, dict):
                            continue
                        yield {
                            "name": dev_name,
                            "address": dev.get("device_address"),
                            "connected": int(group == "device_connected"),
                            "paired": int(group in self._PAIRED_GROUPS),
                            "minor_type": dev.get("device_minorType"),
                            "raw_json": json.dumps(Coerce.jsonable(dev)),
                        }


class WifiCollector(SnapshotCollector):
    slice = slices.WIFI_STATE
    judge_fields = ("ssid", "bssid", "security")

    def collect(self):
        data = CommandRunner().json(
            ["system_profiler", "-json", "SPAirPortDataType"], timeout=30
        )
        sections = (
            data.get("SPAirPortDataType", [])
            if isinstance(data, dict)
            else (data or [])
        )
        for entry in sections:
            for iface in entry.get("spairport_airport_interfaces", []) or []:
                cur = iface.get("spairport_current_network_information") or {}
                channel = cur.get("spairport_network_channel")
                yield {
                    "interface": iface.get("_name"),
                    "ssid": cur.get("_name"),
                    "bssid": cur.get("spairport_network_bssid"),
                    "channel": str(channel) if channel is not None else None,
                    "security": cur.get("spairport_security_mode"),
                    "raw_json": json.dumps(Coerce.jsonable(cur)),
                }


class LinuxUsbDevicesCollector(SnapshotCollector):
    """Linux equivalent of :class:`UsbDevicesCollector`.

    Walks ``/sys/bus/usb/devices`` and reads attribute files (kernel
    exposes the USB descriptors as plain-text files — no parsing
    needed, just :func:`Path.read_text`). Interface sub-nodes (those
    with a ``:`` in their name like ``1-1:1.0``) are skipped — we
    only want device-level entries.
    """

    slice = slices.USB_DEVICES
    judge_fields = ("name", "vendor_id", "product_id", "manufacturer")

    _ATTRS = (
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

    def collect(self):
        root = HostPaths.translate("/sys/bus/usb/devices")
        if not root.is_dir():
            return
        try:
            entries = sorted(root.iterdir(), key=lambda p: p.name)
        except OSError:
            return
        for dev in entries:
            # USB device nodes are named like "1-1", "2-1.2", "usb1".
            # Interfaces (which carry a colon) are sub-descriptors of
            # devices — skip them.
            if ":" in dev.name:
                continue
            if not dev.is_dir():
                continue
            attrs = {a: HostPaths.read_sysfs(dev / a) for a in self._ATTRS}
            attrs = {k: v for k, v in attrs.items() if v is not None}
            if not attrs.get("idVendor") and not attrs.get("product"):
                # Empty entry (e.g. root hubs without descriptors).
                continue
            yield {
                "name": attrs.get("product"),
                "vendor_id": attrs.get("idVendor"),
                "product_id": attrs.get("idProduct"),
                "serial_number": attrs.get("serial"),
                "manufacturer": attrs.get("manufacturer"),
                "location_id": dev.name,
                "speed": attrs.get("speed"),
                "raw_json": json.dumps(attrs),
            }


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

    slice = slices.BLUETOOTH_DEVICES
    judge_fields = ("name", "address", "minor_type")

    def collect(self):
        root = HostPaths.translate("/var/lib/bluetooth")
        if not root.is_dir():
            return
        try:
            adapters = list(root.iterdir())
        except PermissionError:
            return
        for adapter in adapters:
            if not adapter.is_dir():
                continue
            try:
                devices = list(adapter.iterdir())
            except PermissionError:
                continue
            for dev in devices:
                if not dev.is_dir():
                    continue
                info_file = dev / "info"
                if not info_file.is_file():
                    continue
                cp = configparser.ConfigParser(
                    interpolation=None,
                    strict=False,
                    inline_comment_prefixes=("#", ";"),
                )
                # BlueZ info keys are CamelCase (Alias, Name, Class).
                # Preserve case — default lowercasing blanked the
                # device name + class.
                cp.optionxform = str
                try:
                    cp.read(info_file, encoding="utf-8")
                except (configparser.Error, OSError):
                    continue
                general = dict(cp["General"]) if cp.has_section("General") else {}
                # BlueZ stores the MAC with underscores; restore colons.
                mac = dev.name.replace("_", ":")
                full = {sec: dict(cp[sec]) for sec in cp.sections()}
                yield {
                    "name": general.get("Alias") or general.get("Name"),
                    "address": mac,
                    "connected": 0,
                    "paired": 1,
                    "minor_type": general.get("Class"),
                    "raw_json": json.dumps(full),
                }


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

    slice = slices.WIFI_STATE
    judge_fields = ("ssid", "bssid", "security")

    def collect(self):
        # sysfs discovery via HOST_PREFIX; iw queries via netlink which
        # the host-network namespace (network_mode: host) already
        # exposes to the container.
        net = HostPaths.translate("/sys/class/net")
        if not net.is_dir():
            return
        try:
            ifaces = list(net.iterdir())
        except OSError:
            return
        iw_available = shutil.which("iw") is not None
        for iface_dir in ifaces:
            if not (iface_dir / "wireless").is_dir():
                continue
            iface = iface_dir.name
            link = self._iw_link(iface) if iw_available else {}
            yield {
                "interface": iface,
                "ssid": link.get("SSID"),
                "bssid": link.get("BSSID"),
                "channel": link.get("freq"),
                "security": link.get("type"),
                "raw_json": json.dumps(link),
            }

    @staticmethod
    def _iw_link(iface: str) -> dict:
        try:
            r = subprocess.run(
                ["iw", "dev", iface, "link"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return {}
        if r.returncode != 0 or not r.stdout:
            return {}
        out: dict = {}
        for raw in r.stdout.splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith("Connected to"):
                tokens = line.split()
                if len(tokens) >= 3:
                    out["BSSID"] = tokens[2]
                continue
            if line.startswith("Not connected"):
                out["connected"] = "no"
                continue
            key, sep, value = line.partition(":")
            if sep:
                out[key.strip()] = value.strip()
        return out
