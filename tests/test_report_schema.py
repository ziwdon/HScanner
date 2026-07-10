from datetime import UTC, datetime
from pathlib import Path

import pytest

from hscanner.budget import RequestMetrics
from hscanner.errors import ErrorCode
from hscanner.models import (
    Classification,
    ClassificationBucket,
    EngineState,
    FileRecord,
    FileResult,
    LookupStatus,
    OutcomeReason,
    ReportAction,
    ReportCategory,
    RiskLabel,
    ScanOutcome,
    ScanStatus,
)
from hscanner.report import build_scan_report, classify_report_result, report_payload

FIXED_TIME = datetime(2026, 6, 20, 14, 26, tzinfo=UTC)


@pytest.fixture
def make_result():
    def factory(name: str) -> FileResult:
        root = Path("/scan")
        return FileResult(
            record=FileRecord(
                root=root,
                path=root / name,
                size=10,
                mtime_ns=1,
                mode=0o100755,
                is_symlink=False,
                is_regular=True,
                is_hidden=False,
            ),
            classification=Classification(
                bucket=ClassificationBucket.HASH_ONLY,
                reason="hashable file",
                upload_eligible=False,
                hash_eligible=True,
            ),
            sha256="a" * 64,
            action=ReportAction.HASHED,
        )

    return factory


@pytest.fixture
def sample_results(make_result) -> list[FileResult]:
    return [make_result("sample.sh")]


def test_schema_has_versioned_metadata_and_top_level_files(sample_results) -> None:
    report = build_scan_report(
        Path("/scan"),
        sample_results,
        online=True,
        upload_consent=False,
        status=ScanStatus.COMPLETED,
        request_metrics=RequestMetrics.zero(),
        report_id_factory=lambda: "report-id",
        now=lambda: FIXED_TIME,
    )

    payload = report_payload(report)

    assert payload["schema_version"] == 3
    assert payload["report_id"] == "report-id"
    assert payload["generated_at"] == "2026-06-20T14:26:00Z"
    assert isinstance(payload["files"], list)
    assert payload["files"][0]["json_reference"] == "/files/0/raw_result"
    assert {
        "outcome", "outcome_reason", "lookup_status", "upload_status", "engine_checked"
    } <= payload["files"][0].keys()
    assert set(payload["summary"]) == {
        "inventoried", "scanned", "infected", "needs_attention",
        "uploaded", "skipped", "errors", "delay_count",
    }


def test_summary_definitions_do_not_double_count_errors(make_result) -> None:
    clean = make_result("clean.sh")
    clean.engine_state = EngineState.FOUND
    clean.lookup_status = LookupStatus.FOUND
    clean.assessment_complete = True
    clean.engine_stats = {"malicious": 0, "suspicious": 0, "undetected": 70}
    classify_report_result(clean)
    error = make_result("error.sh")
    error.action = ReportAction.FAILED
    error.errors.append(ErrorCode.ENGINE_NETWORK_ERROR)
    classify_report_result(error)
    report = build_scan_report(
        Path("/scan"),
        [error, clean],
        online=True,
        upload_consent=False,
        report_id_factory=lambda: "id",
        now=lambda: FIXED_TIME,
    )

    assert report.summary.errors == 1
    assert report.summary.needs_attention == 0
    assert report.summary.infected == 0
    assert report.summary.scanned == 1


def test_summary_metrics_overlap_without_double_counting_outcomes(make_result) -> None:
    infected = make_result("infected.sh")
    infected.lookup_status = LookupStatus.FOUND
    infected.outcome = ScanOutcome.INFECTED
    infected.outcome_reason = OutcomeReason.ENGINE_DETECTION
    clean = make_result("clean.sh")
    clean.lookup_status = LookupStatus.FOUND
    clean.outcome = ScanOutcome.NO_DETECTIONS
    clean.outcome_reason = OutcomeReason.ENGINE_CLEAN

    report = build_scan_report(
        Path("/scan"), [infected, clean], online=True, upload_consent=False
    )

    assert report.summary.inventoried == 2
    assert report.summary.scanned == 2
    assert report.summary.infected == 1
    assert report.summary.needs_attention == 0


def test_report_records_engine_identity():
    report = build_scan_report(
        Path("/tmp"), [], online=True, upload_consent=False,
        engine_id="metadefender", engine_name="MetaDefender",
    )
    payload = report_payload(report)
    assert payload["engine_id"] == "metadefender"
    assert payload["engine_name"] == "MetaDefender"


def test_report_payload_round_trips_to_scan_report(make_result) -> None:
    from hscanner.report import scan_report_from_payload

    result = make_result("sample.sh")
    result.engine_id = "metadefender"
    result.lookup_status = LookupStatus.FOUND
    result.engine_state = EngineState.FOUND
    result.assessment_complete = True
    result.engine_stats = {"malicious": 0, "suspicious": 0, "undetected": 2}
    result.raw_result = {"scan_results": {"total_avs": 2, "total_detected_avs": 0}}
    classify_report_result(result)
    metrics = RequestMetrics(
        by_kind=(("lookup", 1), ("upload", 0)),
        pacing_wait_count=1,
        pacing_wait_seconds=2.5,
        rate_limit_wait_count=0,
        rate_limit_wait_seconds=0.0,
    )
    report = build_scan_report(
        Path("/scan"),
        [result],
        online=True,
        upload_consent=False,
        engine_id="metadefender",
        engine_name="MetaDefender",
        request_metrics=metrics,
        report_id_factory=lambda: "report-id",
        now=lambda: FIXED_TIME,
        engine_breakdown={"metadefender": 1},
        request_metrics_by_engine={"metadefender": metrics},
    )

    restored = scan_report_from_payload(report_payload(report))

    assert restored.report_id == "report-id"
    assert restored.engine_id == "metadefender"
    assert restored.engine_name == "MetaDefender"
    assert restored.request_metrics.total == 1
    assert restored.request_metrics.pacing_wait_seconds == 2.5
    assert restored.request_metrics_by_engine["metadefender"].by_kind == (
        ("lookup", 1), ("upload", 0)
    )
    assert restored.engine_breakdown == {"metadefender": 1}
    assert restored.summary.scanned == 1
    assert restored.summary.needs_attention == 0
    assert restored.files[0].relative_path == "sample.sh"
    assert restored.files[0].engine_counts == (
        ("malicious", 0), ("suspicious", 0), ("undetected", 2)
    )
    assert restored.files[0].raw_result == {
        "scan_results": {"total_avs": 2, "total_detected_avs": 0}
    }


def test_legacy_infected_payload_derives_matching_medium_fields(make_result) -> None:
    from hscanner.report import scan_report_from_payload

    result = make_result("sample.sh")
    result.lookup_status = LookupStatus.FOUND
    result.engine_state = EngineState.FOUND
    result.assessment_complete = True
    result.engine_stats = {"malicious": 0, "suspicious": 1, "undetected": 4}
    classify_report_result(result)
    report = build_scan_report(
        Path("/scan"),
        [result],
        online=True,
        upload_consent=False,
        report_id_factory=lambda: "report-id",
        now=lambda: FIXED_TIME,
    )
    payload = report_payload(report)
    payload["files"][0].pop("risk_label", None)
    payload["files"][0].pop("report_category", None)

    restored = scan_report_from_payload(payload)

    assert restored.files[0].outcome == ScanOutcome.INFECTED.value
    assert restored.files[0].risk_label == RiskLabel.MEDIUM.value
    assert restored.files[0].report_category == ReportCategory.MEDIUM.value
