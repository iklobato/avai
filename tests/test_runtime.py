"""Unit tests for the injectable runtime collaborators."""

from __future__ import annotations

import sqlite3
import sys

import pytest

from avai.host_monitor.runtime import (
    Clock,
    CommandRunner,
    Digest,
    ExternalSqliteReader,
    FrozenClock,
)


class TestCommandRunner:
    def test_json_parses_stdout(self):
        runner = CommandRunner()
        out = runner.json([sys.executable, "-c", "print('{\"k\": 1}')"])
        assert out == {"k": 1}

    def test_json_empty_stdout_is_none(self):
        runner = CommandRunner()
        assert runner.json([sys.executable, "-c", ""]) is None

    def test_json_nonzero_exit_raises_with_stderr(self):
        runner = CommandRunner()
        with pytest.raises(RuntimeError) as exc:
            runner.json(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stderr.write('boom'); sys.exit(3)",
                ]
            )
        assert "rc=3" in str(exc.value)
        assert "boom" in str(exc.value)

    def test_ndjson_yields_per_line_and_skips_blank_and_malformed(self):
        runner = CommandRunner()
        script = (
            "print('{\"a\": 1}'); print(''); print('not json'); print('{\"b\": 2}')"
        )
        rows = list(runner.ndjson([sys.executable, "-c", script]))
        assert rows == [{"a": 1}, {"b": 2}]

    def test_exit_code_returns_code(self):
        runner = CommandRunner()
        assert runner.exit_code([sys.executable, "-c", "import sys; sys.exit(0)"]) == 0
        assert runner.exit_code([sys.executable, "-c", "import sys; sys.exit(7)"]) == 7

    def test_exit_code_missing_binary_is_none(self):
        runner = CommandRunner()
        assert runner.exit_code(["this-binary-does-not-exist-xyz"]) is None

    def test_exists(self):
        runner = CommandRunner()
        assert runner.exists(sys.executable) or runner.exists("python3")
        assert runner.exists("this-binary-does-not-exist-xyz") is False


class TestClock:
    def test_now_iso_is_utc_second_resolution(self):
        iso = Clock().now_iso()
        assert iso.endswith("+00:00")
        # second resolution: no fractional component
        assert "." not in iso

    def test_frozen_clock_is_deterministic(self):
        clock = FrozenClock("2026-06-03T00:00:00+00:00")
        assert clock.now_iso() == "2026-06-03T00:00:00+00:00"
        assert clock.now_iso() == "2026-06-03T00:00:00+00:00"


class TestDigest:
    def test_sha256_file_roundtrip(self, tmp_path):
        p = tmp_path / "f.bin"
        p.write_bytes(b"hello")
        import hashlib

        assert Digest.sha256_file(p) == hashlib.sha256(b"hello").hexdigest()

    def test_sha256_file_missing_is_none(self, tmp_path):
        assert Digest.sha256_file(tmp_path / "nope") is None

    def test_of_row_is_field_scoped_and_order_independent(self):
        a = Digest.of_row({"name": "x", "extra": 1}, ("name",))
        b = Digest.of_row({"extra": 999, "name": "x"}, ("name",))
        assert a == b  # only declared field participates

    def test_of_row_distinguishes_values(self):
        assert Digest.of_row({"name": "x"}, ("name",)) != Digest.of_row(
            {"name": "y"}, ("name",)
        )

    def test_of_row_no_fields_is_none(self):
        assert Digest.of_row({"name": "x"}, ()) is None

    def test_ssh_fingerprint_known_shape(self):
        import base64
        import hashlib

        raw = b"\x00\x01\x02\x03"
        b64 = base64.b64encode(raw).decode()
        expected = "SHA256:" + base64.b64encode(
            hashlib.sha256(raw).digest()
        ).decode().rstrip("=")
        assert Digest.ssh_fingerprint(b64) == expected

    def test_ssh_fingerprint_bad_input_is_none(self):
        assert Digest.ssh_fingerprint("!!!not base64!!!") is None


class TestExternalSqliteReader:
    def test_reflects_table_and_yields_rows(self, tmp_path):
        db = tmp_path / "ext.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE items (id INTEGER, name TEXT)")
        conn.executemany("INSERT INTO items VALUES (?, ?)", [(1, "a"), (2, "b")])
        conn.commit()
        conn.close()

        rows = list(ExternalSqliteReader().rows(db, "items", ["id", "name"]))
        assert rows == [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]
