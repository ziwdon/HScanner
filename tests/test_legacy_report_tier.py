from pathlib import Path

from hscanner.classifier import classify_file
from hscanner.models import FileRecord, FileResult, ReportAction, RiskTier
from hscanner.policy.loader import load_default_policy
from hscanner.report import (
    _report_file,
    _report_file_payload,
    _report_file_from_payload,
)


def _record(name: str, size: int = 10, mode: int = 0o100755) -> FileRecord:
    return FileRecord(
        root=Path("/scan"), path=Path("/scan") / name,
        size=size, mtime_ns=1, mode=mode,
        is_symlink=False, is_regular=True, is_hidden=False,
    )


def _file_result(name: str, mode: int = 0o100755) -> FileResult:
    cls = classify_file(_record(name, mode=mode), load_default_policy())
    result = FileResult(record=_record(name, mode=mode), classification=cls)
    result.action = ReportAction.HASHED
    return result


_LEGACY_PAYLOAD_SKELETON = {
    "index": 0, "relative_path": "a", "size": 10, "sha256": None,
    "classification_bucket": "upload_candidate", "classification_reason": "x",
    "hash_eligible": True, "upload_eligible": True, "suspicious": True,
    "outcome": "needs_attention", "outcome_reason": "scan_incomplete",
    "lookup_status": "not_checked", "upload_status": "not_uploaded",
    "risk_label": "unknown", "report_category": "full_inventory",
    "action": "hashed", "engine_state": "not_queried",
    "permalink": None, "engine_counts": {},
    "detection_ratio": {"flagged": 0, "total": 0},
    "detections": [], "last_analysis_at": None,
    "analysis_status": "not_applicable",
    "errors": [], "json_reference": "/files/0/raw_result", "raw_result": None,
    "assessment_complete": False, "executable_bit": False,
    "shebang": False, "elf": False, "engine_id": None,
}


def test_report_payload_serializes_risk_tier_for_high():
    result = _file_result("a.sh")
    rf = _report_file(0, result)
    payload = _report_file_payload(rf)
    assert payload["risk_tier"] == "high"


def test_report_payload_serializes_risk_tier_for_medium():
    result = _file_result("a.py", mode=0o100644)
    rf = _report_file(0, result)
    payload = _report_file_payload(rf)
    assert payload["risk_tier"] == "medium"


def test_report_payload_roundtrips_risk_tier():
    result = _file_result("a.py", mode=0o100644)
    rf = _report_file(0, result)
    payload = _report_file_payload(rf)
    restored = _report_file_from_payload(payload)
    assert restored.risk_tier == "medium"


def test_legacy_payload_without_risk_tier_maps_to_high_for_upload_candidate():
    payload = dict(_LEGACY_PAYLOAD_SKELETON)
    rf = _report_file_from_payload(payload)
    assert rf.risk_tier == "high"


def test_legacy_payload_without_risk_tier_maps_to_low_risk_for_hash_only():
    payload = dict(_LEGACY_PAYLOAD_SKELETON)
    payload["classification_bucket"] = "hash_only"
    rf = _report_file_from_payload(payload)
    assert rf.risk_tier == "low_risk"


def test_legacy_payload_without_risk_tier_maps_to_skipped_for_skipped():
    payload = dict(_LEGACY_PAYLOAD_SKELETON)
    payload["classification_bucket"] = "skipped"
    rf = _report_file_from_payload(payload)
    assert rf.risk_tier == "skipped"