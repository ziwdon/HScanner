import pytest

from hscanner.cache import EngineCache
from hscanner.engines.base import EngineInfo
from hscanner.progress import EventType
from hscanner.scanner import run_online_scan, single_engine_rotation
from hscanner.store import open_global_store


class FakeClient:
    info = EngineInfo(id="virustotal", display_name="VirusTotal", default_per_minute=4)

    async def get_file_report(self, sha):
        return None

    def metrics_snapshot(self):
        from hscanner.budget import RequestMetrics

        return RequestMetrics.zero()

    async def close(self):
        pass


@pytest.mark.asyncio
async def test_scan_started_carries_online_pending_and_bypassed(tmp_path, monkeypatch):
    # Keep XDG_STATE_HOME outside the scan root so state DB files don't pollute the traversal.
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    scan_root = tmp_path / "data"
    scan_root.mkdir()
    (scan_root / "movie.mp4").write_bytes(b"\x00data")
    (scan_root / "a.sh").write_text("#!/bin/sh\n")
    events = []
    await run_online_scan(
        scan_root, single_engine_rotation(FakeClient()), upload_consent=False,
        cache=EngineCache(open_global_store()), bypass_low_risk=True,
        observer=events.append,
    )
    started = next(e for e in events if e.type == EventType.SCAN_STARTED)
    assert started.online_pending == 1
    assert started.bypassed == 1
