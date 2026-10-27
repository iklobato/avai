"""Every error avai raises on purpose shares one base, AvaiError, while keeping
the stdlib base its callers already catch."""

from __future__ import annotations

import logging

import pytest

from avai.enrichers.base import EnricherError, RateLimitedError
from avai.enrichers.http import RetriesExhaustedError
from avai.errors import AvaiError, UnsupportedPlatformError
from avai.host_monitor.db_bootstrap import SchemaMigrationError
from avai.host_monitor.hosts.factory import HostFactory
from avai.host_monitor.llm import CompletionError
from avai.host_monitor.runtime.command_runner import CommandFailedError
from avai.host_monitor.runtime.row_source import MissingToolError
from avai.hostsfile import (
    HostsAccessDeniedError,
    HostsError,
    HostsPermissionError,
    PlatformResolver,
)


class TestAvaiErrorFamily:
    @pytest.mark.parametrize(
        "error",
        [
            EnricherError,
            RateLimitedError,
            RetriesExhaustedError,
            SchemaMigrationError,
            CompletionError,
            CommandFailedError,
            MissingToolError,
            HostsError,
            HostsAccessDeniedError,
            HostsPermissionError,
            UnsupportedPlatformError,
        ],
    )
    def test_every_own_error_is_an_avai_error(self, error: type[Exception]) -> None:
        assert issubclass(error, AvaiError)

    @pytest.mark.parametrize(
        "error",
        [
            SchemaMigrationError,
            CompletionError,
            CommandFailedError,
            MissingToolError,
            HostsError,
            UnsupportedPlatformError,
        ],
    )
    def test_runtime_errors_stay_runtime_errors(self, error: type[Exception]) -> None:
        assert issubclass(error, RuntimeError)


class TestUnsupportedPlatform:
    def test_host_factory_raises_the_shared_error(self) -> None:
        with pytest.raises(UnsupportedPlatformError) as excinfo:
            HostFactory(logging.getLogger("test")).create("Plan9")

        assert excinfo.value.system == "Plan9"
        assert str(excinfo.value) == (
            "avai has no host implementation for platform: 'Plan9'"
        )

    def test_hosts_file_raises_the_shared_error_as_a_hosts_error(self) -> None:
        with pytest.raises(UnsupportedPlatformError) as excinfo:
            PlatformResolver().resolve("Plan9")

        assert isinstance(excinfo.value, HostsError)
        assert str(excinfo.value) == (
            "avai cannot manage the hosts file on platform 'Plan9'"
        )
