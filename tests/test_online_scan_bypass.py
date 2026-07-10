import pytest

from hscanner.cache import EngineCache
from hscanner.engines.base import EngineInfo
from hscanner.models import EngineState, LookupStatus, OutcomeReason, ScanOutcome
from hscanner.scanner import run_online_scan, single_engine_rotation
from hscanner.store import open_global_store


class FakeClient:
    info = EngineInfo(id="virustotal", display_name="VirusTotal", default_per_minute=4)

    def __init__(self):
        self.looked_up = []

    async def get_file_report(self, sha):
        self.looked_up.append(sha)
        return None  # NOT_FOUND

    def metrics_snapshot(self):
        from hscanner.budget import RequestMetrics

        return RequestMetrics.zero()

    async def close(self):
        pass


@pytest.mark.asyncio
async def test_bypass_skips_low_risk_lookup(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "movie.mp4").write_bytes(b"\x00\x01\x02data")
    (scan_dir / "scene.rpy").write_text("label start:\n    return\n")
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hi\n")
    client = FakeClient()
    cache = EngineCache(open_global_store())
    outcome = await run_online_scan(
        scan_dir, single_engine_rotation(client), upload_consent=False, cache=cache,
        bypass_low_risk=True,
    )
    by_name = {r.record.path.name: r for r in outcome.results}
    assert by_name["movie.mp4"].engine_state == EngineState.NOT_QUERIED
    assert by_name["movie.mp4"].lookup_status == LookupStatus.NOT_CHECKED
    assert by_name["movie.mp4"].outcome == ScanOutcome.SKIPPED
    assert by_name["movie.mp4"].outcome_reason == OutcomeReason.LOW_RISK
    assert by_name["scene.rpy"].engine_state == EngineState.NOT_FOUND
    assert by_name["scene.rpy"].lookup_status == LookupStatus.NOT_FOUND
    assert by_name["scene.rpy"].outcome == ScanOutcome.NEEDS_ATTENTION
    assert by_name["scene.rpy"].outcome_reason == OutcomeReason.ENGINE_NOT_FOUND
    assert by_name["tool.sh"].engine_state == EngineState.NOT_FOUND
    assert by_name["tool.sh"].lookup_status == LookupStatus.NOT_FOUND
    assert by_name["tool.sh"].outcome == ScanOutcome.NEEDS_ATTENTION
    assert by_name["tool.sh"].outcome_reason == OutcomeReason.ENGINE_NOT_FOUND
    assert len(client.looked_up) == 2  # script + unrecognized file
    assert outcome.engine_breakdown == {"virustotal": 2, "not_checked": 1}


@pytest.mark.asyncio
async def test_no_bypass_looks_up_everything(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "movie.mp4").write_bytes(b"\x00\x01\x02data")
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hi\n")
    client = FakeClient()
    cache = EngineCache(open_global_store())
    outcome = await run_online_scan(
        scan_dir, single_engine_rotation(client), upload_consent=False, cache=cache,
        bypass_low_risk=False,
    )
    assert len(client.looked_up) == 2
    assert all(result.lookup_status == LookupStatus.NOT_FOUND for result in outcome.results)
