"""Tests for the dashboard launcher's URL formatting and bind-failure path —
notably reaching the dashboard at http://avai.local (port 80)."""

from __future__ import annotations

import errno

import pytest

from avai.dashboard import serve


class TestHttpUrl:
    def test_port_80_is_omitted(self):
        assert serve._http_url("avai.local", 80) == "http://avai.local"

    def test_non_default_port_is_shown(self):
        assert serve._http_url("avai.local", 8765) == "http://avai.local:8765"


class TestBindErrorMessage:
    def test_privileged_port_denied_suggests_sudo(self):
        msg = serve._bind_error_message(
            "127.0.0.1", 80, PermissionError(errno.EACCES, "denied")
        )
        assert "sudo avai dashboard --port 80" in msg

    def test_high_port_permission_error_is_not_misreported_as_privilege(self):
        msg = serve._bind_error_message(
            "127.0.0.1", 8765, PermissionError(errno.EACCES, "denied")
        )
        assert "elevated privileges" not in msg

    def test_address_in_use_is_reported(self):
        msg = serve._bind_error_message(
            "127.0.0.1", 80, OSError(errno.EADDRINUSE, "in use")
        )
        assert "already in use" in msg


class TestServeSurfacesBindFailure:
    def test_privileged_bind_failure_exits_with_message_not_traceback(
        self, monkeypatch
    ):
        def _denied(*_a, **_k):
            raise PermissionError(errno.EACCES, "denied")

        monkeypatch.setattr(serve, "_run_server", _denied)
        monkeypatch.setattr(serve, "_hosts_notice", lambda _port: [])

        with pytest.raises(SystemExit) as excinfo:
            serve._serve("127.0.0.1", 80, debug=False)
        assert "needs elevated privileges" in str(excinfo.value)
