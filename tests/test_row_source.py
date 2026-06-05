"""Tests for the snapshot RowSource collaborators."""

from __future__ import annotations

import pytest

from avai.host_monitor.runtime import CommandSnapshot, FileSnapshot


class _FakeRunner:
    def __init__(self, *, exists=True, text=""):
        self._exists = exists
        self._text = text
        self.called_with = None

    def exists(self, name):
        return self._exists

    def text(self, cmd, timeout=10):
        self.called_with = (cmd, timeout)
        return self._text


class _UpperParser:
    """Trivial parser: one row per non-blank line."""

    def parse(self, text):
        return [{"line": ln.strip().upper()} for ln in text.splitlines() if ln.strip()]


class TestCommandSnapshot:
    def test_runs_command_and_parses(self):
        runner = _FakeRunner(text="a\n\nb\n")
        rows = list(CommandSnapshot(runner, ["arp", "-an"], _UpperParser()).rows())
        assert rows == [{"line": "A"}, {"line": "B"}]
        assert runner.called_with[0] == ["arp", "-an"]

    def test_missing_binary_raises(self):
        runner = _FakeRunner(exists=False)
        with pytest.raises(RuntimeError) as exc:
            list(CommandSnapshot(runner, ["nope"], _UpperParser()).rows())
        assert "nope" in str(exc.value)

    def test_passes_timeout(self):
        runner = _FakeRunner(text="")
        list(CommandSnapshot(runner, ["x"], _UpperParser(), timeout=99).rows())
        assert runner.called_with[1] == 99


class TestFileSnapshot:
    def test_reads_and_parses(self, tmp_path):
        p = tmp_path / "f"
        p.write_text("one\ntwo\n")
        rows = list(FileSnapshot(p, _UpperParser()).rows())
        assert rows == [{"line": "ONE"}, {"line": "TWO"}]

    def test_missing_file_is_empty_not_error(self, tmp_path):
        rows = list(FileSnapshot(tmp_path / "absent", _UpperParser()).rows())
        assert rows == []
