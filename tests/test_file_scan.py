"""Tests for YARA file scanning (FileScanCollector) and the offline
hash deny-list enricher.

Pure-filesystem + pure-logic: a temp dir stands in for the scan targets
and a temp rules dir supplies a controlled rule, so these run anywhere
with no real malware and no network. The one exception is a smoke test
that the *bundled* EICAR rule actually compiles — that guards against a
broken shipped rule disabling scanning.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import yara

import avai.host_monitor.constants as C
from avai.enrichers.base import Indicator, IndicatorType, VerdictHint
from avai.enrichers.indicators import extract_indicators
from avai.enrichers.registry import discover_enricher_classes
from avai.enrichers.sources.local_denylist import LocalHashDenylistEnricher
from avai.host_monitor.collectors import (
    FileScanCollector,
    _compile_yara_rules,
    _crypto_hint,
    _file_type,
)

_MARKER = "AVAITESTMATCH"
_RULE = 'rule avai_test {{ strings: $a = "{m}" condition: $a }}'.format(m=_MARKER)


class _FakeFs:
    """Minimal FilesystemLayout: every target source is explicit so each
    test exercises exactly one path."""

    def __init__(self, bin_dirs=(), app_exes=(), homes=()):
        self._bin_dirs = list(bin_dirs)
        self._app_exes = list(app_exes)
        self._homes = list(homes)

    def privileged_bin_dirs(self):
        return self._bin_dirs

    def app_executables(self):
        return self._app_exes

    def home_dirs(self):
        return self._homes


def _rules_dir(tmp_path: Path) -> Path:
    d = tmp_path / "rules"
    d.mkdir()
    (d / "avai_test.yar").write_text(_RULE)
    return d


# ---------------------------------------------------------------------------
# FileScanCollector
# ---------------------------------------------------------------------------


class TestFileScanCollector:
    def test_match_in_bin_dir_emits_row(self, tmp_path):
        bindir = tmp_path / "bin"
        bindir.mkdir()
        hit = bindir / "evil.bin"
        hit.write_text(_MARKER)
        (bindir / "clean.txt").write_text("nothing to see")

        fs = _FakeFs(bin_dirs=[bindir])
        rows = list(FileScanCollector(fs=fs, rules_dir=_rules_dir(tmp_path)).collect())

        assert len(rows) == 1
        row = rows[0]
        assert row["rule"] == "avai_test"
        assert row["path"] == str(hit)
        assert row["scan_source"] == "bin_dirs"
        assert row["namespace"] == "avai_test"
        assert row["sha256"] and len(row["sha256"]) == 64
        assert row["size"] == len(_MARKER)

    def test_clean_file_emits_nothing(self, tmp_path):
        bindir = tmp_path / "bin"
        bindir.mkdir()
        (bindir / "clean.bin").write_text("benign content")
        fs = _FakeFs(bin_dirs=[bindir])
        rows = list(FileScanCollector(fs=fs, rules_dir=_rules_dir(tmp_path)).collect())
        assert rows == []

    def test_no_rules_dir_yields_nothing(self, tmp_path):
        bindir = tmp_path / "bin"
        bindir.mkdir()
        (bindir / "evil.bin").write_text(_MARKER)
        fs = _FakeFs(bin_dirs=[bindir])
        # Point at a dir with no .yar files → compile returns None → no scan.
        empty = tmp_path / "empty"
        empty.mkdir()
        rows = list(FileScanCollector(fs=fs, rules_dir=empty).collect())
        assert rows == []

    def test_oversized_file_is_skipped(self, tmp_path, monkeypatch):
        bindir = tmp_path / "bin"
        bindir.mkdir()
        (bindir / "evil.bin").write_text(_MARKER)
        monkeypatch.setattr(C, "YARA_MAX_FILE_BYTES", 1)  # smaller than the marker
        fs = _FakeFs(bin_dirs=[bindir])
        rows = list(FileScanCollector(fs=fs, rules_dir=_rules_dir(tmp_path)).collect())
        assert rows == []

    def test_unreadable_file_does_not_abort_scan(self, tmp_path):
        # A file that vanishes/!is_file mid-walk must be skipped, not fatal:
        # a dangling symlink (is_file() False, stat() raises) sits beside a
        # real match; the real match must still come through.
        bindir = tmp_path / "bin"
        bindir.mkdir()
        (bindir / "dangling").symlink_to(tmp_path / "does-not-exist")
        good = bindir / "evil.bin"
        good.write_text(_MARKER)
        fs = _FakeFs(bin_dirs=[bindir])
        rows = list(FileScanCollector(fs=fs, rules_dir=_rules_dir(tmp_path)).collect())
        assert [r["path"] for r in rows] == [str(good)]

    def test_unreadable_target_dir_is_skipped(self, tmp_path):
        # Regression: Path.is_dir() re-raises EACCES (it only swallows
        # ENOENT/ENOTDIR), which previously aborted the whole collector on
        # an unreadable dir like /var/root/Applications. The unreadable dir
        # must be skipped and a readable sibling still scanned.
        locked_parent = tmp_path / "locked"
        locked_parent.mkdir()
        unreadable = locked_parent / "bin"  # child under a 000 parent → EACCES
        good_dir = tmp_path / "good"
        good_dir.mkdir()
        match = good_dir / "evil.bin"
        match.write_text(_MARKER)
        os.chmod(locked_parent, 0o000)
        try:
            fs = _FakeFs(bin_dirs=[unreadable, good_dir])
            rows = list(
                FileScanCollector(fs=fs, rules_dir=_rules_dir(tmp_path)).collect()
            )
        finally:
            os.chmod(locked_parent, 0o755)  # restore so tmp cleanup works
        assert [r["path"] for r in rows] == [str(match)]

    def test_app_executable_target_labelled(self, tmp_path):
        exe = tmp_path / "App.app" / "Contents" / "MacOS" / "App"
        exe.parent.mkdir(parents=True)
        exe.write_text(_MARKER)
        fs = _FakeFs(app_exes=[exe])
        rows = list(FileScanCollector(fs=fs, rules_dir=_rules_dir(tmp_path)).collect())
        assert len(rows) == 1
        assert rows[0]["scan_source"] == "app_bundle"

    def test_downloads_only_recent_files_scanned(self, tmp_path):
        home = tmp_path / "home"
        dl = home / "Downloads"
        dl.mkdir(parents=True)
        recent = dl / "fresh.bin"
        recent.write_text(_MARKER)
        old = dl / "stale.bin"
        old.write_text(_MARKER)
        # Push the old file's mtime well past the recent window.
        old_epoch = recent.stat().st_mtime - (C.YARA_DOWNLOADS_RECENT_DAYS + 5) * 86400
        os.utime(old, (old_epoch, old_epoch))

        fs = _FakeFs(homes=[home])
        rows = list(FileScanCollector(fs=fs, rules_dir=_rules_dir(tmp_path)).collect())
        assert [r["path"] for r in rows] == [str(recent)]
        assert rows[0]["scan_source"] == "downloads"

    def test_per_cycle_cap_bounds_scan(self, tmp_path, monkeypatch):
        bindir = tmp_path / "bin"
        bindir.mkdir()
        for i in range(3):
            (bindir / f"evil{i}.bin").write_text(_MARKER)
        monkeypatch.setattr(C, "YARA_MAX_FILES_PER_CYCLE", 1)
        fs = _FakeFs(bin_dirs=[bindir])
        rows = list(FileScanCollector(fs=fs, rules_dir=_rules_dir(tmp_path)).collect())
        assert len(rows) == 1  # only one file scanned before the cap

    def test_no_fs_yields_nothing(self, tmp_path):
        rows = list(
            FileScanCollector(fs=None, rules_dir=_rules_dir(tmp_path)).collect()
        )
        assert rows == []

    def test_bundled_eicar_rules_compile(self):
        # Guards against a broken shipped rule silently disabling scanning.
        rules, stats = _compile_yara_rules(C.YARA_RULES_DIR)
        assert rules is not None
        assert stats["rules_loaded"] >= 1
        assert "bundled" in stats["sources"]
        # inventory carries one entry per rule, tagged with source/category
        assert len(stats["inventory"]) == stats["rules_loaded"]
        eicar = next(
            e for e in stats["inventory"] if e["identifier"] == "eicar_test_file"
        )
        assert eicar["source"] == "bundled"
        assert eicar["category"] == "eicar"


class TestYaraExternals:
    """signature-base rules reference scanner externals; the collector must
    define them at compile and supply real per-file values at match."""

    def _rules(self, tmp_path: Path, body: str) -> Path:
        d = tmp_path / "rules"
        d.mkdir()
        (d / "ext.yar").write_text(body)
        return d

    def test_filename_external_compiles_and_matches(self, tmp_path):
        # Without externals support this rule fails to compile
        # ("undefined identifier"); it must compile AND gate on the name.
        rules = self._rules(tmp_path, 'rule t { condition: filename == "evil.bin" }')
        bindir = tmp_path / "bin"
        bindir.mkdir()
        (bindir / "evil.bin").write_text("anything")
        (bindir / "innocent.txt").write_text("anything")
        rows = list(
            FileScanCollector(fs=_FakeFs(bin_dirs=[bindir]), rules_dir=rules).collect()
        )
        assert [Path(r["path"]).name for r in rows] == ["evil.bin"]

    def test_filetype_external_gates_on_magic(self, tmp_path):
        rules = self._rules(tmp_path, 'rule t { condition: filetype == "EXE" }')
        bindir = tmp_path / "bin"
        bindir.mkdir()
        (bindir / "real.exe").write_bytes(b"MZ\x90\x00binary")
        (bindir / "notes.txt").write_text("plain text, not an exe")
        rows = list(
            FileScanCollector(fs=_FakeFs(bin_dirs=[bindir]), rules_dir=rules).collect()
        )
        assert [Path(r["path"]).name for r in rows] == ["real.exe"]

    def test_meta_retained_on_finding(self, tmp_path):
        rules = self._rules(
            tmp_path,
            'rule t { meta: author = "Jane Doe" reference = "https://x" '
            f'strings: $a = "{_MARKER}" condition: $a }}',
        )
        bindir = tmp_path / "bin"
        bindir.mkdir()
        (bindir / "evil.bin").write_text(_MARKER)
        rows = list(
            FileScanCollector(fs=_FakeFs(bin_dirs=[bindir]), rules_dir=rules).collect()
        )
        assert len(rows) == 1
        meta = json.loads(rows[0]["meta_json"])
        assert meta["author"] == "Jane Doe"
        assert meta["reference"] == "https://x"

    def test_crypto_rule_file_does_not_disable_others(self, tmp_path):
        # A hash.* rule file (needs crypto yara) sits beside a plain rule.
        # The plain rule must still compile and match regardless of whether
        # this yara build has crypto (skip) or not (compiles, just no match).
        d = tmp_path / "rules"
        d.mkdir()
        (d / "good.yar").write_text(
            f'rule good {{ strings: $a = "{_MARKER}" condition: $a }}'
        )
        (d / "crypto.yar").write_text(
            'import "hash"\nrule c { condition: hash.md5(0, filesize) == "x" }'
        )
        bindir = tmp_path / "bin"
        bindir.mkdir()
        (bindir / "evil.bin").write_text(_MARKER)
        rows = list(
            FileScanCollector(fs=_FakeFs(bin_dirs=[bindir]), rules_dir=d).collect()
        )
        assert any(r["rule"] == "good" for r in rows)


class TestFileType:
    def test_detects_known_magics(self, tmp_path):
        cases = {
            b"MZ\x90\x00": "EXE",
            b"\x7fELF\x02\x01": "ELF",
            b"\xcf\xfa\xed\xfe": "MACH-O",
            b"MDMP\x93\xa7": "MDMP",
        }
        for header, expected in cases.items():
            f = tmp_path / f"f_{expected}"
            f.write_bytes(header + b"\x00\x00\x00\x00")
            assert _file_type(f) == expected

    def test_unknown_and_unreadable_return_empty(self, tmp_path):
        text = tmp_path / "plain.txt"
        text.write_text("just text")
        assert _file_type(text) == ""
        assert _file_type(tmp_path / "does-not-exist") == ""


class TestCryptoHint:
    def test_imphash_error_gets_actionable_hint(self):
        hint = _crypto_hint(yara.Error('invalid field name "imphash"'))
        assert "crypto-enabled yara" in hint and "NOTICE" in hint

    def test_unrelated_error_gets_no_hint(self):
        assert _crypto_hint(yara.Error("syntax error, unexpected '}'")) == ""


# ---------------------------------------------------------------------------
# LocalHashDenylistEnricher
# ---------------------------------------------------------------------------


class TestLocalHashDenylist:
    def _denylist(self, tmp_path: Path, body: str) -> Path:
        f = tmp_path / "denylist.txt"
        f.write_text(body)
        return f

    def test_known_hash_is_malicious(self, tmp_path):
        bad = "a" * 64
        enricher = LocalHashDenylistEnricher(path=self._denylist(tmp_path, bad + "\n"))
        ev = enricher._fetch(Indicator(IndicatorType.SHA256, bad))
        assert ev is not None
        assert ev.verdict_hint is VerdictHint.MALICIOUS
        assert ev.source == "local_denylist"
        assert ev.confidence == 1.0

    def test_unknown_hash_no_opinion(self, tmp_path):
        enricher = LocalHashDenylistEnricher(
            path=self._denylist(tmp_path, "a" * 64 + "\n")
        )
        assert enricher._fetch(Indicator(IndicatorType.SHA256, "b" * 64)) is None

    def test_comments_and_case_are_handled(self, tmp_path):
        # Upper-case entry + trailing comment; indicators arrive lowercased.
        body = "# header\n" + ("F" * 32) + "  # a known-bad md5\n"
        enricher = LocalHashDenylistEnricher(path=self._denylist(tmp_path, body))
        assert enricher._fetch(Indicator(IndicatorType.MD5, "f" * 32)) is not None

    def test_missing_file_gives_no_opinion(self, tmp_path):
        enricher = LocalHashDenylistEnricher(path=tmp_path / "absent.txt")
        assert enricher._fetch(Indicator(IndicatorType.SHA256, "c" * 64)) is None

    def test_registered_keyless_in_registry(self):
        classes = discover_enricher_classes()
        assert LocalHashDenylistEnricher in classes
        # Keyless ⇒ env_token returns the always-on sentinel (never None).
        assert LocalHashDenylistEnricher.env_token() is not None


# ---------------------------------------------------------------------------
# FileScanExtractor (via the public dispatch)
# ---------------------------------------------------------------------------


class TestFileScanExtractor:
    def test_emits_sha256_indicator(self):
        inds = extract_indicators("file_scan", {"sha256": "a" * 64, "path": "/bin/x"})
        assert len(inds) == 1
        assert inds[0].type is IndicatorType.SHA256
        assert inds[0].context["path"] == "/bin/x"

    def test_no_sha_no_indicator(self):
        assert extract_indicators("file_scan", {"path": "/bin/x"}) == []
