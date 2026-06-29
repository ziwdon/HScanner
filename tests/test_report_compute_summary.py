# tests/test_report_compute_summary.py
from pathlib import Path

from hscanner.budget import RequestMetrics
from hscanner.classifier import classify_file
from hscanner.models import FileRecord, FileResult
from hscanner.policy.loader import load_default_policy
from hscanner.report import build_scan_report, compute_summary, report_payload


def _result(name: str) -> FileResult:
    root = Path("/scan")
    rec = FileRecord(root=root, path=root / name, size=10, mtime_ns=0, mode=0o644,
                     is_symlink=False, is_regular=True, is_hidden=False)
    res = FileResult(record=rec, classification=classify_file(rec, load_default_policy()))
    res.sha256 = "a" * 64
    return res


def test_compute_summary_matches_build_scan_report():
    results = [_result("a.sh"), _result("b.mp4")]
    report = build_scan_report(Path("/scan"), results, online=True, upload_consent=False)
    recomputed = compute_summary(report.files, RequestMetrics.zero())
    assert recomputed.inventoried == report.summary.inventoried
    assert recomputed.scanned == report.summary.scanned
    assert recomputed.needs_attention == report.summary.needs_attention


def test_report_payload_includes_signal_fields():
    res = _result("launcher")
    res.elf = True
    report = build_scan_report(Path("/scan"), [res], online=True, upload_consent=False)
    payload_file = report_payload(report)["files"][0]
    assert payload_file["elf"] is True
    assert "assessment_complete" in payload_file
