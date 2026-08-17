import csv
import io
import json
from pathlib import Path

from hscanner.classifier import classify_file
from hscanner.exporters import render_csv, render_json
from hscanner.models import FileRecord, FileResult, ReportAction
from hscanner.policy.loader import load_default_policy
from hscanner.report import build_scan_report


def _record(name: str, size: int = 10, mode: int = 0o100755) -> FileRecord:
    return FileRecord(
        root=Path("/scan"), path=Path("/scan") / name,
        size=size, mtime_ns=1, mode=mode,
        is_symlink=False, is_regular=True, is_hidden=False,
    )


def test_csv_has_risk_tier_column_after_classification_reason():
    cls = classify_file(_record("a.sh"), load_default_policy())
    result = FileResult(record=_record("a.sh"), classification=cls)
    result.action = ReportAction.HASHED
    report = build_scan_report(
        root=Path("/scan"), results=[result],
        online=True, upload_consent=False,
        engine_id="virustotal", engine_name="Test",
    )
    text = render_csv(report)
    reader = csv.reader(io.StringIO(text))
    header = next(reader)
    assert "risk_tier" in header
    assert header.index("risk_tier") == header.index("classification_reason") + 1


def test_json_payload_includes_risk_tier_per_file():
    cls = classify_file(_record("a.sh"), load_default_policy())
    result = FileResult(record=_record("a.sh"), classification=cls)
    result.action = ReportAction.HASHED
    report = build_scan_report(
        root=Path("/scan"), results=[result],
        online=True, upload_consent=False,
        engine_id="virustotal", engine_name="Test",
    )
    payload = json.loads(render_json(report))
    assert payload["files"][0]["risk_tier"] == "high"