from pathlib import Path

import pytest

from hscanner.cache import EngineCache
from hscanner.engines.base import EngineFileReport, EngineInfo
from hscanner.engines.rotation import EngineRotation, EngineSlot
from hscanner.errors import ErrorCode, HScannerError
from hscanner.models import LookupStatus, ScanOutcome
from hscanner.scanner import scan_single_file_with_rotation
from hscanner.store import open_global_store


class FoundEngine:
    def __init__(self, engine_id: str, report: EngineFileReport) -> None:
        self.info = EngineInfo(engine_id, engine_id.title(), default_per_minute=4)
        self.report = report
        self.lookups = 0
        self.uploads = 0

    async def get_file_report(self, sha256: str):
        self.lookups += 1
        return self.report

    async def upload_file(self, path: Path) -> str:
        self.uploads += 1
        return "analysis-id"

    async def wait_for_analysis(self, analysis_id: str, sha256: str):
        return self.report

    async def close(self) -> None:
        pass


class RateLimitedEngine(FoundEngine):
    async def get_file_report(self, sha256: str):
        self.lookups += 1
        raise HScannerError(
            ErrorCode.ENGINE_RATE_LIMITED,
            "rate limited",
            retry_after=600.0,
        )


@pytest.mark.asyncio
async def test_single_file_rotation_uses_single_engine_found_result(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    root = tmp_path / "scan"
    root.mkdir()
    (root / "tool.sh").write_text("#!/bin/sh\necho hi\n")
    report = EngineFileReport(
        engine_stats={"malicious": 0, "undetected": 4},
        assessment_complete=True,
    )
    engine = FoundEngine("virustotal", report)

    result = await scan_single_file_with_rotation(
        root,
        "tool.sh",
        EngineRotation([EngineSlot(engine)]),
        EngineCache(open_global_store()),
    )

    assert result.engine_id == "virustotal"
    assert result.lookup_status == LookupStatus.FOUND
    assert result.outcome == ScanOutcome.NO_DETECTIONS
    assert engine.lookups == 1
    assert engine.uploads == 0


@pytest.mark.asyncio
async def test_single_file_rotation_fails_over_to_next_engine(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    root = tmp_path / "scan"
    root.mkdir()
    (root / "tool.sh").write_text("#!/bin/sh\necho hi\n")
    report = EngineFileReport(
        engine_stats={"malicious": 0, "undetected": 2},
        assessment_complete=True,
    )
    first = RateLimitedEngine("virustotal", report)
    second = FoundEngine("metadefender", report)

    result = await scan_single_file_with_rotation(
        root,
        "tool.sh",
        EngineRotation([EngineSlot(first), EngineSlot(second)], wait_threshold=1.0),
        EngineCache(open_global_store()),
    )

    assert result.engine_id == "metadefender"
    assert result.lookup_status == LookupStatus.FOUND
    assert result.outcome == ScanOutcome.NO_DETECTIONS
    assert first.lookups == 1
    assert second.lookups == 1
