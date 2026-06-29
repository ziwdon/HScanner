from hscanner.cache import EngineCache
from hscanner.engines.base import EngineFileReport, EngineInfo
from hscanner.models import EngineState, ScanStatus
from hscanner.progress import EventType, ScanController, ScanStage
from hscanner.scanner import run_online_scan, single_engine_rotation
from hscanner.store import open_global_store

CLEAN = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 70}
        }
    }
}
REPORT = EngineFileReport(
    engine_stats={"malicious": 0, "suspicious": 0, "undetected": 70},
    assessment_complete=True,
    raw=CLEAN,
)


class FakeVTClient:
    info = EngineInfo(id="virustotal", display_name="VirusTotal", default_per_minute=4)

    def __init__(self, *, controller=None, cancel_on_lookup=False) -> None:
        self.hooks = None
        self.lookups: list[str] = []
        self._controller = controller
        self._cancel_on_lookup = cancel_on_lookup

    async def get_file_report(self, sha256: str):
        self.lookups.append(sha256)
        if self._cancel_on_lookup and self._controller is not None:
            self._controller.cancel()
        return REPORT  # FOUND

    async def upload_file(self, path):  # not used here
        return "x"

    async def wait_for_analysis(self, analysis_id, sha256):
        return REPORT

    def metrics_snapshot(self):
        from hscanner.budget import RequestMetrics

        return RequestMetrics.zero()


def _write(root, name):
    p = root / name
    p.write_text("#!/bin/sh\n", encoding="utf-8")
    p.chmod(0o755)


def _cache(tmp_path):
    return EngineCache(open_global_store(base_dir=tmp_path / "c"), ttl_days=7)


async def test_observer_receives_event_sequence(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    _write(root, "a.sh")
    events = []
    outcome = await run_online_scan(
        root, single_engine_rotation(FakeVTClient()), upload_consent=False,
        cache=_cache(tmp_path), observer=events.append,
    )
    types = [e.type for e in events]
    assert types[0] == EventType.SCAN_STARTED
    assert events[0].total == 1
    assert EventType.FILE_STARTED in types
    lookup_events = [
        event for event in events
        if event.type == EventType.STAGE_CHANGED and event.stage == ScanStage.LOOKUP
    ]
    assert lookup_events
    assert lookup_events[0].engine_id == "virustotal"
    assert EventType.FILE_FINISHED in types
    finished = next(event for event in events if event.type == EventType.FILE_FINISHED)
    assert finished.engine_id == "virustotal"
    assert finished.outcome == "no_detections"
    assert finished.outcome_reason == "engine_clean"
    assert finished.lookup_status == "found"
    assert finished.upload_status == "not_uploaded"
    assert types[-1] == EventType.SCAN_FINISHED
    assert events[-1].status == ScanStatus.COMPLETED.value
    assert outcome.status == ScanStatus.COMPLETED


async def test_cancel_before_scan_yields_cancelled_status(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    _write(root, "a.sh")
    controller = ScanController()
    controller.cancel()
    events = []
    outcome = await run_online_scan(
        root, single_engine_rotation(FakeVTClient()), upload_consent=False,
        cache=_cache(tmp_path), controller=controller, observer=events.append,
    )
    assert outcome.status == ScanStatus.CANCELLED
    # No file reached a VT verdict because the first checkpoint cancelled.
    assert all(r.engine_state != EngineState.FOUND for r in outcome.results)
    finished = [event for event in events if event.type == EventType.FILE_FINISHED]
    assert len(finished) == len(outcome.results)
    assert finished[0].outcome == "needs_attention"


async def test_cancel_midscan_stops_remaining_files(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    _write(root, "a.sh")
    _write(root, "b.sh")
    controller = ScanController()
    fake = FakeVTClient(controller=controller, cancel_on_lookup=True)
    outcome = await run_online_scan(
        root, single_engine_rotation(fake), upload_consent=False,
        cache=_cache(tmp_path), controller=controller,
    )
    assert outcome.status == ScanStatus.CANCELLED
    assert len(fake.lookups) == 1  # cancelled after the first file's lookup
