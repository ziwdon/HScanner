from pathlib import Path

from hscanner.classifier import classify_file
from hscanner.errors import ErrorCode
from hscanner.models import (
    EngineState,
    FileRecord,
    FileResult,
    LookupStatus,
    OutcomeReason,
    ScanOutcome,
)
from hscanner.policy.loader import load_default_policy
from hscanner.report import build_scan_report, classify_report_result
from hscanner.report_view import build_report_view


def _result(name: str, *, elf=False, size=100) -> FileResult:
    root = Path("/scan")
    rec = FileRecord(root=root, path=root / name, size=size, mtime_ns=0, mode=0o644,
                     is_symlink=False, is_regular=True, is_hidden=False)
    res = FileResult(record=rec, classification=classify_file(rec, load_default_policy()))
    res.sha256 = "a" * 64
    res.elf = elf
    res.engine_state = EngineState.NOT_FOUND
    res.lookup_status = LookupStatus.NOT_FOUND
    return classify_report_result(res)


def _view_for(res):
    report = build_scan_report(Path("/scan"), [res], online=True, upload_consent=False)
    view = build_report_view(report)
    for sec in view["sections"]:
        for f in sec["files"]:
            return f
    return None


def test_unknown_priority_file_can_scan():
    f = _view_for(_result("tool.sh"))
    assert f["can_scan"] is True
    assert f["too_large"] is False


def test_upload_eligible_error_file_can_scan():
    result = _result("tool.sh")
    result.outcome = ScanOutcome.ERROR
    result.errors.append(ErrorCode.ANALYSIS_TIMEOUT)
    f = _view_for(result)
    assert f["can_scan"] is True


def test_elf_badge_present():
    f = _view_for(_result("tool.sh", elf=True))
    assert "ELF" in f["badges"]


def test_view_exposes_file_engine_and_engine_breakdown():
    result = _result("tool.sh")
    result.engine_id = "virustotal"
    report = build_scan_report(
        Path("/scan"),
        [result],
        online=True,
        upload_consent=False,
        engine_id="combined",
        engine_name="Combined",
        engine_breakdown={"virustotal": 1},
    )

    view = build_report_view(report)
    file = view["sections"][0]["files"][0]

    assert file["scan_engine"] == "VirusTotal"
    assert file["lookup_status"] == "Not found"
    assert file["upload_status"] == "Not uploaded"
    assert view["engine_breakdown"] == {"virustotal": 1}


def test_view_uses_ordered_outcome_sections_and_tiles():
    outcomes = [
        (ScanOutcome.INFECTED, OutcomeReason.ENGINE_DETECTION),
        (ScanOutcome.NEEDS_ATTENTION, OutcomeReason.ENGINE_NOT_FOUND),
        (ScanOutcome.NO_DETECTIONS, OutcomeReason.ENGINE_CLEAN),
        (ScanOutcome.SKIPPED, OutcomeReason.LOW_RISK),
        (ScanOutcome.ERROR, OutcomeReason.SCAN_INCOMPLETE),
    ]
    results = []
    for index, (outcome, reason) in enumerate(outcomes):
        result = _result(f"file-{index}.sh")
        result.outcome = outcome
        result.outcome_reason = reason
        results.append(result)
    report = build_scan_report(Path("/scan"), results, online=True, upload_consent=False)

    view = build_report_view(report)

    assert [section["id"] for section in view["sections"]] == [
        "infected", "needs-attention", "no-detections", "skipped", "errors"
    ]
    assert [tile["k"] for tile in view["tiles"]] == [
        "Inventoried", "Scanned", "Infected", "Needs attention",
        "Uploaded", "Skipped", "Errors",
    ]
