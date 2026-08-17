from pathlib import Path

from hscanner.classifier import classify_file
from hscanner.models import FileRecord, FileResult, ReportAction, ScanOutcome
from hscanner.policy.loader import load_default_policy
from hscanner.report import build_scan_report
from hscanner.report_view import _RISK_GROUP_META, build_report_view


def test_risk_group_meta_has_three_groups():
    keys = {m["key"] for m in _RISK_GROUP_META.values()}
    assert keys == {"high", "medium", "low_risk"}


def test_risk_group_order_is_high_medium_low_risk():
    keys = [m["key"] for m in _RISK_GROUP_META.values()]
    assert keys == ["high", "medium", "low_risk"]


def _record(name: str, mode: int = 0o100644) -> FileRecord:
    return FileRecord(
        root=Path("/scan"), path=Path("/scan") / name,
        size=10, mtime_ns=1, mode=mode,
        is_symlink=False, is_regular=True, is_hidden=False,
    )


def _make_result(name: str, mode: int = 0o100644) -> FileResult:
    cls = classify_file(_record(name, mode=mode), load_default_policy())
    result = FileResult(record=_record(name, mode=mode), classification=cls)
    result.action = ReportAction.HASHED
    result.outcome = ScanOutcome.NEEDS_ATTENTION
    return result


def test_needs_attention_renders_high_medium_low_risk_groups():
    files = [
        _make_result("a.sh", mode=0o755),       # HIGH
        _make_result("z.py", mode=0o644),       # MEDIUM
        _make_result("data.json", mode=0o644),  # LOW_RISK
    ]
    report = build_scan_report(
        root=Path("/scan"), results=files,
        online=True, upload_consent=False,
        engine_id="virustotal", engine_name="Test",
    )
    view = build_report_view(report)
    section = next(s for s in view["sections"] if s["outcome"] == "needs_attention")
    group_keys = [g["key"] for g in section["groups"]]
    assert group_keys == ["high", "medium", "low_risk"]
    high_group = next(g for g in section["groups"] if g["key"] == "high")
    medium_group = next(g for g in section["groups"] if g["key"] == "medium")
    low_group = next(g for g in section["groups"] if g["key"] == "low_risk")
    assert high_group["total"] == 1     # a.sh
    assert medium_group["total"] == 1  # z.py
    assert low_group["total"] == 1     # data.json
    chip_keys = [c["key"] for c in section["risk_chips"]]
    assert chip_keys == ["high", "medium", "low_risk"]
    pill_keys = [p["key"] for p in section["filters"]]
    assert pill_keys == ["all", "high", "medium", "low_risk"]