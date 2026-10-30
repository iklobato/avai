"""The capabilities snapshot the monitor writes for the Setup panel."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from avai.host_monitor import ControlState
from avai.host_monitor.capabilities import CapabilitiesProbe, SourceCoverage, StageFlags
from avai.host_monitor.main import MonitorArgs, MonitorWiring

FAKE_SECRET = "value-that-must-never-be-stored"


class KeyedSource:
    name = "virustotal"
    requires_token = "VT_API_KEY"


class FreeSource:
    name = "osv"
    requires_token = None


class FakeCatalog:
    def classes(self) -> list[type]:
        return [KeyedSource, FreeSource]


class FakeChain:
    sources = ["osv"]


class TestMonitorStart:
    def test_building_the_monitor_writes_the_snapshot(self, tmp_path: Path) -> None:
        db = str(tmp_path / "m.db")
        flags = ["--db", db, "--no-judge", "--no-enrich", "--no-streaming"]
        flags += ["--no-verify", "--no-investigate"]
        args = MonitorArgs().options(flags)
        _, engine = MonitorWiring(args, logging.getLogger("test")).build()
        with Session(engine) as session:
            stored = session.execute(select(ControlState.capabilities_json)).scalar()
        engine.dispose()
        snapshot = json.loads(stored)
        assert snapshot["judge_model"] is None
        assert snapshot["sources_on"] == []
        assert (snapshot["verify"], snapshot["investigate"]) == (False, False)


class TestCapabilitiesProbe:
    def probe(self, environ: dict[str, str]) -> dict:
        stages = StageFlags(
            judge_model="claude-haiku-4-5", verify=True, investigate=False
        )
        probe = CapabilitiesProbe(SourceCoverage(FakeCatalog()), environ)
        return json.loads(probe.probe(stages, FakeChain()).to_json())

    def test_sources_on_and_missing_keys_are_named(self) -> None:
        snapshot = self.probe({"AVAI_TELEMETRY": "0"})
        assert snapshot["sources_on"] == ["osv"]
        assert snapshot["sources_missing_key"] == [
            {"name": "virustotal", "key": "VT_API_KEY"}
        ]
        assert snapshot["judge_model"] == "claude-haiku-4-5"
        assert (snapshot["verify"], snapshot["investigate"]) == (True, False)
        assert snapshot["telemetry_on"] is False

    def test_no_key_value_ever_reaches_the_snapshot(self) -> None:
        text = json.dumps(
            self.probe({"VT_API_KEY": FAKE_SECRET, "AVAI_TELEMETRY": "1"})
        )
        assert FAKE_SECRET not in text

    def test_without_enrichment_every_keyed_source_is_missing(self) -> None:
        coverage = SourceCoverage(FakeCatalog())
        assert coverage.on(None) == ()
        assert [gap.name for gap in coverage.missing_key(None)] == ["virustotal"]
