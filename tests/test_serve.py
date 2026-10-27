"""Tests for the dashboard launcher's URL formatting and bind-failure path:
notably reaching the dashboard at http://avai.local (port 80)."""

from __future__ import annotations

import errno
import io
from unittest.mock import MagicMock, patch

import pytest

from avai.dashboard.serve import DashboardServer, DashboardUrl, ServeOptions
from avai.hostsfile import HostsError


class TestHttpUrl:
    def test_port_80_is_omitted(self) -> None:
        assert DashboardUrl().http("avai.local", 80) == "http://avai.local"

    def test_non_default_port_is_shown(self) -> None:
        assert DashboardUrl().http("avai.local", 8765) == "http://avai.local:8765"


class TestBindErrorMessage:
    def _message(self, port: int, err: OSError) -> str:
        server = DashboardServer(MagicMock(), io.StringIO())
        return server.bind_error_message(ServeOptions("127.0.0.1", port), err)

    def test_privileged_port_denied_suggests_sudo(self) -> None:
        msg = self._message(80, PermissionError(errno.EACCES, "denied"))
        assert "sudo avai dashboard --port 80" in msg

    def test_high_port_permission_error_is_not_misreported_as_privilege(self) -> None:
        msg = self._message(8765, PermissionError(errno.EACCES, "denied"))
        assert "elevated privileges" not in msg

    def test_address_in_use_is_reported(self) -> None:
        msg = self._message(80, OSError(errno.EADDRINUSE, "in use"))
        assert "already in use" in msg


class TestServeSurfacesBindFailure:
    def test_privileged_bind_failure_exits_with_message_not_traceback(self) -> None:
        denied = PermissionError(errno.EACCES, "denied")
        server = DashboardServer(MagicMock(), io.StringIO())
        with (
            patch("waitress.serve", side_effect=denied),
            patch(
                "avai.dashboard.serve.HostsRegistrar.for_current_platform",
                side_effect=HostsError("no hosts file"),
            ),
            pytest.raises(SystemExit) as excinfo,
        ):
            server.serve(ServeOptions("127.0.0.1", 80))
        assert "needs elevated privileges" in str(excinfo.value)
