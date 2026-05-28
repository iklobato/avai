"""Tests for the browser-extension readers — the Chromium and
Firefox manifest parsers used by ``browser_extensions`` collector.

These run against synthesized on-disk profile structures so we can
verify the parsing logic without launching a real browser.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from avai.host_monitor import (
    Browser,
    ChromiumExtensionReader,
    FirefoxExtensionReader,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _chromium_profile(base: Path, profile: str, ext_id: str,
                      version: str, manifest: dict) -> None:
    ext_dir = base / profile / "Extensions" / ext_id / version
    ext_dir.mkdir(parents=True, exist_ok=True)
    (ext_dir / "manifest.json").write_text(json.dumps(manifest),
                                           encoding="utf-8")


def _firefox_profile(base: Path, profile: str, addons: list[dict]) -> None:
    p = base / "Profiles" / profile
    p.mkdir(parents=True, exist_ok=True)
    (p / "extensions.json").write_text(
        json.dumps({"addons": addons}), encoding="utf-8")


# ---------------------------------------------------------------------------
# Chromium
# ---------------------------------------------------------------------------

class TestChromiumReader:
    def test_reads_one_extension(self, tmp_path):
        _chromium_profile(tmp_path, "Default",
                          "abcdefghijklmnopabcdefghijklmnop",
                          "1.0.0",
                          {"name": "Test Ext", "version": "1.0.0",
                           "permissions": ["tabs", "<all_urls>"],
                           "host_permissions": ["https://*/*"]})
        rows = list(ChromiumExtensionReader().read(tmp_path, Browser.CHROME))
        assert len(rows) == 1
        r = rows[0]
        assert r["browser"] == "chrome"
        assert r["profile"] == "Default"
        assert r["extension_id"] == "abcdefghijklmnopabcdefghijklmnop"
        assert r["name"] == "Test Ext"
        assert r["version"] == "1.0.0"
        assert json.loads(r["permissions_json"]) == ["tabs", "<all_urls>"]
        assert json.loads(r["host_permissions_json"]) == ["https://*/*"]

    def test_walks_multiple_profiles(self, tmp_path):
        _chromium_profile(tmp_path, "Default", "a" * 32, "1.0", {"name": "A"})
        _chromium_profile(tmp_path, "Profile 1", "b" * 32, "1.0", {"name": "B"})
        rows = list(ChromiumExtensionReader().read(tmp_path, Browser.CHROME))
        profiles = sorted(r["profile"] for r in rows)
        assert profiles == ["Default", "Profile 1"]

    def test_walks_multiple_versions_per_extension(self, tmp_path):
        _chromium_profile(tmp_path, "Default", "a" * 32, "1.0", {"name": "v1"})
        _chromium_profile(tmp_path, "Default", "a" * 32, "1.1", {"name": "v1.1"})
        rows = list(ChromiumExtensionReader().read(tmp_path, Browser.CHROME))
        names = sorted(r["name"] for r in rows)
        assert names == ["v1", "v1.1"]

    def test_skips_extension_without_manifest(self, tmp_path):
        # An extension directory exists but no manifest.json — skipped.
        ext_dir = tmp_path / "Default" / "Extensions" / ("a" * 32) / "1.0"
        ext_dir.mkdir(parents=True)
        rows = list(ChromiumExtensionReader().read(tmp_path, Browser.CHROME))
        assert rows == []

    def test_skips_malformed_manifest_json(self, tmp_path):
        ext_dir = tmp_path / "Default" / "Extensions" / ("a" * 32) / "1.0"
        ext_dir.mkdir(parents=True)
        (ext_dir / "manifest.json").write_text("not { valid json")
        # Must not raise — corrupt manifest is skipped.
        rows = list(ChromiumExtensionReader().read(tmp_path, Browser.CHROME))
        assert rows == []

    def test_returns_nothing_when_base_does_not_exist(self, tmp_path):
        rows = list(ChromiumExtensionReader().read(
            tmp_path / "no-such-dir", Browser.CHROME))
        assert rows == []

    def test_uses_matches_when_host_permissions_missing(self, tmp_path):
        # Manifest v2 used `matches` instead of `host_permissions`.
        _chromium_profile(tmp_path, "Default", "a" * 32, "1.0",
                          {"name": "Old", "matches": ["http://*/*"]})
        rows = list(ChromiumExtensionReader().read(tmp_path, Browser.CHROME))
        assert json.loads(rows[0]["host_permissions_json"]) == ["http://*/*"]

    def test_missing_optional_fields_default_to_empty(self, tmp_path):
        _chromium_profile(tmp_path, "Default", "a" * 32, "1.0",
                          {"name": "Bare"})  # no permissions / hosts
        rows = list(ChromiumExtensionReader().read(tmp_path, Browser.CHROME))
        assert rows[0]["permissions_json"] == "[]"
        assert rows[0]["host_permissions_json"] == "[]"


# ---------------------------------------------------------------------------
# Firefox
# ---------------------------------------------------------------------------

class TestFirefoxReader:
    def test_reads_extensions_json_addon_list(self, tmp_path):
        _firefox_profile(tmp_path, "abc.default-release", [
            {"id": "test@ext",
             "version": "2.0.0",
             "defaultLocale": {"name": "Firefox Ext"},
             "userPermissions": {"permissions": ["tabs"],
                                 "origins": ["<all_urls>"]},
             "path": "/x/y"},
        ])
        rows = list(FirefoxExtensionReader().read(tmp_path, Browser.FIREFOX))
        assert len(rows) == 1
        r = rows[0]
        assert r["browser"] == "firefox"
        assert r["profile"] == "abc.default-release"
        assert r["extension_id"] == "test@ext"
        assert r["name"] == "Firefox Ext"
        assert r["version"] == "2.0.0"
        assert json.loads(r["permissions_json"]) == ["tabs"]
        assert json.loads(r["host_permissions_json"]) == ["<all_urls>"]

    def test_walks_multiple_profiles(self, tmp_path):
        _firefox_profile(tmp_path, "abc.default", [{"id": "a@x"}])
        _firefox_profile(tmp_path, "xyz.dev",     [{"id": "b@x"}])
        rows = list(FirefoxExtensionReader().read(tmp_path, Browser.FIREFOX))
        profiles = sorted(r["profile"] for r in rows)
        assert profiles == ["abc.default", "xyz.dev"]

    def test_skips_profile_without_extensions_json(self, tmp_path):
        # Profile dir exists but no extensions.json.
        (tmp_path / "Profiles" / "barren").mkdir(parents=True)
        rows = list(FirefoxExtensionReader().read(tmp_path, Browser.FIREFOX))
        assert rows == []

    def test_skips_corrupt_extensions_json(self, tmp_path):
        p = tmp_path / "Profiles" / "broken"
        p.mkdir(parents=True)
        (p / "extensions.json").write_text("not json")
        rows = list(FirefoxExtensionReader().read(tmp_path, Browser.FIREFOX))
        assert rows == []

    def test_returns_nothing_without_profiles_dir(self, tmp_path):
        rows = list(FirefoxExtensionReader().read(tmp_path, Browser.FIREFOX))
        assert rows == []

    def test_missing_user_permissions_default_to_empty(self, tmp_path):
        _firefox_profile(tmp_path, "p", [{"id": "x@y", "version": "1"}])
        rows = list(FirefoxExtensionReader().read(tmp_path, Browser.FIREFOX))
        assert rows[0]["permissions_json"] == "[]"
        assert rows[0]["host_permissions_json"] == "[]"
