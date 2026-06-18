"""Tests for the security-control abstraction.

The point of the abstraction is testability: every control is exercised with
fake capabilities, so the enabled-vs-active logic — including the
socket-activated false-negative regression — is verified deterministically
with no OS calls.
"""

from __future__ import annotations

import pytest

from avai.host_monitor.runtime import tri_or
from avai.host_monitor.security_controls import NetworkServiceControl, ServiceSpec

SSH = ServiceSpec("remote_login", "com.openssh.sshd", 22, "sshd")


class FakeServiceManager:
    def __init__(self, enabled=None):
        self._enabled = enabled

    def enabled(self, unit):
        return self._enabled


class FakePortInspector:
    def __init__(self, listening=None, established=None):
        self._listening = listening
        self._established = established

    def listening(self, port):
        return self._listening

    def established(self, port):
        return self._established


class FakeProcessInspector:
    def __init__(self, running=None):
        self._running = running

    def running(self, name):
        return self._running


def _control(svc=None, listening=None, established=None, running=None):
    return NetworkServiceControl(
        SSH,
        FakeServiceManager(svc),
        FakePortInspector(listening=listening, established=established),
        FakeProcessInspector(running=running),
    )


# ---- tri_or -------------------------------------------------------------


@pytest.mark.parametrize(
    "values,expected",
    [
        ((1, 0), 1),
        ((0, 1), 1),
        ((0, 0), 0),
        ((0, None), 0),
        ((None, None), None),
        ((None, 1), 1),
    ],
)
def test_tri_or(values, expected):
    assert tri_or(*values) == expected


# ---- NetworkServiceControl ---------------------------------------------


def test_enabled_but_idle_is_reported_enabled_not_off():
    # The regression: launchd holds the socket (port listening) but the
    # daemon process isn't spawned and there's no peer. The old pgrep-only
    # check reported this as "off"; it must now be enabled=ON, active=OFF.
    f = _control(svc=None, listening=1, established=0, running=0).inspect()
    assert f.enabled == 1
    assert f.active == 0


def test_enabled_via_service_manager_without_ports():
    # No port visibility (non-root → None) but the service manager says
    # enabled — still enabled.
    f = _control(svc=1, listening=None, established=None, running=0).inspect()
    assert f.enabled == 1
    assert f.active == 0


def test_genuinely_off():
    f = _control(svc=0, listening=0, established=0, running=0).inspect()
    assert f.enabled == 0
    assert f.active == 0


def test_active_session():
    # A live peer + running daemon → enabled and active.
    f = _control(svc=1, listening=1, established=1, running=1).inspect()
    assert f.enabled == 1
    assert f.active == 1


def test_all_unknown_stays_unknown():
    f = _control(svc=None, listening=None, established=None, running=None).inspect()
    assert f.enabled is None
    assert f.active is None


def test_topic_is_exposed():
    assert _control().topic == "remote_login"


# ---- collector wiring (end-to-end regression) ---------------------------


def test_macos_collector_maps_enabled_idle_service_to_on():
    """The macOS collector, given an enabled-but-idle service, writes
    ``..._enabled = 1`` (not 0) and keeps the live-session signal in
    raw_json. Mac-only config commands degrade gracefully off-platform."""
    import json

    from avai.host_monitor.collectors import SystemIntegrityCollector

    col = SystemIntegrityCollector(
        services=FakeServiceManager(1),
        ports=FakePortInspector(listening=0, established=0),
        processes=FakeProcessInspector(running=0),
    )
    row = list(col.collect())[0]
    assert row["remote_login_enabled"] == 1
    assert row["screen_sharing_enabled"] == 1
    assert row["remote_management_enabled"] == 1
    services = json.loads(row["raw_json"])["services"]
    assert services["remote_login"] == {"enabled": 1, "active": 0}
