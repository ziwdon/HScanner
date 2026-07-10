# tests/test_report_registry_update.py
from pathlib import Path

from hscanner.classifier import classify_file
from hscanner.models import (
    EngineState,
    FileRecord,
    FileResult,
    LookupStatus,
    ReportAction,
    UploadStatus,
)
from hscanner.policy.loader import load_default_policy
from hscanner.report import build_scan_report
from hscanner.web.persistent_reports import PersistentReportStore
from hscanner.web.report_store import ReportRegistry


def _result(name: str) -> FileResult:
    root = Path("/scan")
    rec = FileRecord(root=root, path=root / name, size=10, mtime_ns=0, mode=0o644,
                     is_symlink=False, is_regular=True, is_hidden=False)
    res = FileResult(record=rec, classification=classify_file(rec, load_default_policy()))
    res.sha256 = "a" * 64
    return res


def test_update_file_replaces_verdict_and_recomputes_summary():
    reg = ReportRegistry()
    report = build_scan_report(Path("/scan"), [_result("a.sh")], online=True, upload_consent=False)
    reg.put(report)
    assert report.summary.infected == 0

    updated = _result("a.sh")
    updated.engine_state = EngineState.UPLOADED
    updated.lookup_status = LookupStatus.NOT_FOUND
    updated.upload_status = UploadStatus.ANALYSIS_COMPLETE
    updated.action = ReportAction.ANALYSIS_COMPLETED
    updated.assessment_complete = True
    updated.engine_stats = {"malicious": 5, "harmless": 60}
    updated.detections = [{"engine": "X", "category": "malicious", "name": "Trojan"}]

    new_report = reg.update_file(report.report_id, 0, updated)
    assert new_report is not None
    assert new_report.summary.infected == 1
    assert new_report.summary.uploaded == 1
    assert reg.get(report.report_id).files[0].outcome == "infected"
    assert reg.get(report.report_id).files[0].lookup_status == "not_found"
    assert reg.get(report.report_id).files[0].upload_status == "analysis_complete"


def test_update_file_unknown_report_returns_none():
    reg = ReportRegistry()
    assert reg.update_file("nope", 0, _result("a.sh")) is None


def test_update_file_persists_updated_report(tmp_path):
    db_path = tmp_path / "reports.db"
    store = PersistentReportStore(path=db_path)
    reg = ReportRegistry(persistent_store=store)
    report = build_scan_report(Path("/scan"), [_result("a.sh")], online=True, upload_consent=False)
    reg.put(report)

    updated = _result("a.sh")
    updated.engine_state = EngineState.UPLOADED
    updated.lookup_status = LookupStatus.NOT_FOUND
    updated.upload_status = UploadStatus.ANALYSIS_COMPLETE
    updated.action = ReportAction.ANALYSIS_COMPLETED
    updated.assessment_complete = True
    updated.engine_stats = {"malicious": 5, "harmless": 60}
    updated.detections = [{"engine": "X", "category": "malicious", "name": "Trojan"}]

    reg.update_file(report.report_id, 0, updated)
    reg.flush(report.report_id)
    restored = ReportRegistry(
        persistent_store=PersistentReportStore(path=db_path)
    ).get(report.report_id)

    assert restored is not None
    assert restored.summary.infected == 1
    assert restored.summary.uploaded == 1
    assert restored.files[0].outcome == "infected"


class RecordingPersistentStore:
    def __init__(self) -> None:
        self.puts = []

    def put(self, report):
        self.puts.append(report)

    def get(self, report_id):
        for report in reversed(self.puts):
            if report.report_id == report_id:
                return report
        return None


def test_update_file_throttles_persistent_writes_until_flush():
    clock = [0.0]
    store = RecordingPersistentStore()
    reg = ReportRegistry(
        persistent_store=store,
        monotonic=lambda: clock[0],
        persistent_update_interval=2.0,
    )
    report = build_scan_report(
        Path("/scan"),
        [_result("a.sh"), _result("b.sh"), _result("c.sh")],
        online=True,
        upload_consent=False,
    )
    reg.put(report)

    reg.update_file(report.report_id, 0, _result("a.sh"))
    reg.update_file(report.report_id, 1, _result("b.sh"))
    reg.update_file(report.report_id, 2, _result("c.sh"))

    assert len(store.puts) == 1

    reg.flush(report.report_id)

    assert len(store.puts) == 2
    assert store.puts[-1].report_id == report.report_id
