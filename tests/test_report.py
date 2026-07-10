import json
from pathlib import Path

from hscanner.errors import ErrorCode
from hscanner.models import (
    Classification,
    ClassificationBucket,
    EngineState,
    FileRecord,
    FileResult,
    LookupStatus,
    OutcomeReason,
    ReportCategory,
    RiskLabel,
    ScanOutcome,
)
from hscanner.report import (
    build_scan_report,
    classify_report_result,
    cli_exit_code,
    report_payload,
)


def make_result(
    bucket: ClassificationBucket,
    engine_state: EngineState,
    engine_stats: dict | None = None,
    errors: list | None = None,
) -> FileResult:
    record = FileRecord(Path("/scan"), Path("/scan/tool.sh"), 10, 1, 0o100755, False, True, False)
    result = FileResult(
        record=record,
        classification=Classification(
            bucket,
            "reason",
            bucket == ClassificationBucket.UPLOAD_CANDIDATE,
            bucket != ClassificationBucket.SKIPPED,
            suspicious=True,
        ),
        engine_state=engine_state,
        lookup_status={
            EngineState.FOUND: LookupStatus.FOUND,
            EngineState.UPLOADED: LookupStatus.NOT_FOUND,
            EngineState.NOT_FOUND: LookupStatus.NOT_FOUND,
        }.get(engine_state, LookupStatus.NOT_CHECKED),
    )
    if engine_stats is not None:
        result.engine_stats = engine_stats
        result.assessment_complete = True
    if errors is not None:
        result.errors = errors
    return result


def test_explicit_outcome_matrix() -> None:
    infected = classify_report_result(make_result(
        ClassificationBucket.HASH_ONLY,
        EngineState.FOUND,
        engine_stats={"malicious": 1},
    ))
    suspicious = classify_report_result(make_result(
        ClassificationBucket.HASH_ONLY,
        EngineState.FOUND,
        engine_stats={"suspicious": 1},
    ))
    clean = classify_report_result(make_result(
        ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED,
        EngineState.FOUND,
        engine_stats={"malicious": 0, "suspicious": 0, "undetected": 10},
    ))
    incomplete = classify_report_result(make_result(
        ClassificationBucket.HASH_ONLY, EngineState.FOUND
    ))
    unknown = classify_report_result(make_result(
        ClassificationBucket.UPLOAD_CANDIDATE, EngineState.NOT_FOUND
    ))

    assert (infected.outcome, infected.outcome_reason) == (
        ScanOutcome.INFECTED, OutcomeReason.ENGINE_DETECTION
    )
    assert suspicious.outcome == ScanOutcome.INFECTED
    assert (clean.outcome, clean.outcome_reason) == (
        ScanOutcome.NO_DETECTIONS, OutcomeReason.ENGINE_CLEAN
    )
    assert (incomplete.outcome, incomplete.outcome_reason) == (
        ScanOutcome.NEEDS_ATTENTION, OutcomeReason.INCOMPLETE_ENGINE_RESULT
    )
    assert (unknown.outcome, unknown.outcome_reason) == (
        ScanOutcome.NEEDS_ATTENTION, OutcomeReason.ENGINE_NOT_FOUND
    )


def test_error_outcome_uses_first_error_code() -> None:
    result = classify_report_result(make_result(
        ClassificationBucket.HASH_ONLY,
        EngineState.NOT_QUERIED,
        errors=[ErrorCode.PERMISSION_DENIED, ErrorCode.HASH_FAILED],
    ))

    assert result.outcome == ScanOutcome.ERROR
    assert result.outcome_reason == ErrorCode.PERMISSION_DENIED


def test_unknown_oversized_priority_file_is_upload_blocked_attention() -> None:
    result = classify_report_result(make_result(
        ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED, EngineState.NOT_FOUND
    ))

    assert result.outcome == ScanOutcome.NEEDS_ATTENTION
    assert result.outcome_reason == OutcomeReason.UPLOAD_BLOCKED


def test_explicit_engine_detection_without_aggregate_counts_is_infected() -> None:
    result = make_result(ClassificationBucket.HASH_ONLY, EngineState.FOUND)
    result.detections = [
        {"engine": "Example AV", "category": "malicious", "name": "Example"}
    ]

    classify_report_result(result)

    assert result.outcome == ScanOutcome.INFECTED
    assert result.outcome_reason == OutcomeReason.ENGINE_DETECTION


def test_unknown_upload_candidate_is_unknown_but_suspicious() -> None:
    result = classify_report_result(
        make_result(ClassificationBucket.UPLOAD_CANDIDATE, EngineState.NOT_FOUND)
    )

    assert result.risk_label == RiskLabel.UNKNOWN
    assert result.report_category == ReportCategory.UNKNOWN_BUT_SUSPICIOUS


def test_upload_blocked_is_medium_attention() -> None:
    result = classify_report_result(
        make_result(ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED, EngineState.NOT_FOUND)
    )

    assert result.risk_label == RiskLabel.MEDIUM
    assert result.report_category == ReportCategory.UPLOAD_BLOCKED


def test_unknown_but_suspicious_trips_exit_one() -> None:
    result = classify_report_result(
        make_result(ClassificationBucket.UPLOAD_CANDIDATE, EngineState.NOT_FOUND)
    )
    report = build_scan_report(Path("/scan"), [result], online=False, upload_consent=False)

    assert cli_exit_code(report) == 1


def test_report_payload_structure() -> None:
    result = classify_report_result(
        make_result(ClassificationBucket.UPLOAD_CANDIDATE, EngineState.NOT_FOUND)
    )
    report = build_scan_report(Path("/scan"), [result], online=False, upload_consent=False)

    payload = report_payload(report)

    assert payload["schema_version"] == 3
    assert "files" in payload
    assert len(payload["files"]) == 1
    entry = payload["files"][0]
    assert entry["relative_path"] == "tool.sh"
    assert entry["size"] == 10
    assert "sha256" in entry
    assert "classification_bucket" in entry
    assert "classification_reason" in entry
    assert entry["outcome"] == ScanOutcome.NEEDS_ATTENTION.value
    assert entry["outcome_reason"] == OutcomeReason.ENGINE_NOT_FOUND.value
    assert entry["lookup_status"] == LookupStatus.NOT_FOUND.value
    assert entry["engine_checked"] is True
    assert "risk_label" not in entry
    assert "report_category" not in entry
    assert "engine_state" not in entry
    assert "engine_counts" in entry
    assert "permalink" in entry
    assert "errors" in entry


def test_report_payload_no_api_key_leak() -> None:
    result = classify_report_result(
        make_result(ClassificationBucket.HASH_ONLY, EngineState.NOT_QUERIED)
    )
    report = build_scan_report(Path("/scan"), [result], online=False, upload_consent=False)

    payload = report_payload(report)

    assert "api_key" not in json.dumps(payload)


# --- New tests for fixes #2 and #3 ---


def test_skipped_bucket_maps_to_skipped() -> None:
    result = classify_report_result(
        make_result(ClassificationBucket.SKIPPED, EngineState.NOT_QUERIED)
    )

    assert result.risk_label == RiskLabel.SKIPPED
    assert result.report_category == ReportCategory.SKIPPED


def test_upload_blocked_with_detections_upgrades_to_high() -> None:
    # Fix #3: SUSPICIOUS_UPLOAD_BLOCKED + malicious detections → HIGH (not UPLOAD_BLOCKED)
    result = classify_report_result(
        make_result(
            ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED,
            EngineState.FOUND,
            engine_stats={"malicious": 5},
        )
    )

    assert result.risk_label == RiskLabel.HIGH
    assert result.report_category == ReportCategory.HIGH


def test_upload_blocked_no_detections_stays_upload_blocked() -> None:
    result = classify_report_result(
        make_result(ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED, EngineState.NOT_FOUND)
    )

    assert result.report_category == ReportCategory.UPLOAD_BLOCKED


def test_uploaded_clean_file_maps_to_no_detections() -> None:
    # Fix #2: EngineState.UPLOADED + clean stats → NO_DETECTIONS (not FULL_INVENTORY/UNKNOWN)
    result = classify_report_result(
        make_result(
            ClassificationBucket.UPLOAD_CANDIDATE,
            EngineState.UPLOADED,
            engine_stats={"malicious": 0, "suspicious": 0, "undetected": 70},
        )
    )

    assert result.risk_label == RiskLabel.NO_DETECTIONS
    assert result.report_category == ReportCategory.NO_DETECTIONS


def test_found_file_with_many_detections_maps_to_high() -> None:
    result = classify_report_result(
        make_result(
            ClassificationBucket.HASH_ONLY,
            EngineState.FOUND,
            engine_stats={"malicious": 3},
        )
    )

    assert result.risk_label == RiskLabel.HIGH
    assert result.report_category == ReportCategory.HIGH


def test_errors_list_maps_to_errors_category_and_exit_code_2() -> None:
    result = classify_report_result(
        make_result(
            ClassificationBucket.HASH_ONLY,
            EngineState.NOT_QUERIED,
            errors=[ErrorCode.PERMISSION_DENIED],
        )
    )

    assert result.report_category == ReportCategory.ERRORS
    report = build_scan_report(Path("/scan"), [result], online=False, upload_consent=False)
    assert cli_exit_code(report) == 2


def test_hash_only_found_clean_maps_to_no_detections() -> None:
    result = classify_report_result(
        make_result(
            ClassificationBucket.HASH_ONLY,
            EngineState.FOUND,
            engine_stats={"malicious": 0, "suspicious": 0, "undetected": 55},
        )
    )

    assert result.risk_label == RiskLabel.NO_DETECTIONS
    assert result.report_category == ReportCategory.NO_DETECTIONS


def test_hash_only_not_queried_maps_to_full_inventory() -> None:
    result = classify_report_result(
        make_result(ClassificationBucket.HASH_ONLY, EngineState.NOT_QUERIED)
    )

    assert result.risk_label == RiskLabel.UNKNOWN
    assert result.report_category == ReportCategory.FULL_INVENTORY


def test_one_suspicious_detection_maps_to_medium() -> None:
    result = classify_report_result(
        make_result(
            ClassificationBucket.HASH_ONLY,
            EngineState.FOUND,
            engine_stats={"malicious": 0, "suspicious": 1},
        )
    )

    assert result.outcome == ScanOutcome.INFECTED
    assert result.risk_label == RiskLabel.MEDIUM
    assert result.report_category == ReportCategory.MEDIUM


def test_low_risk_bypass_maps_to_skipped_legacy_fields() -> None:
    result = make_result(ClassificationBucket.HASH_ONLY, EngineState.NOT_QUERIED)
    result.outcome_reason = OutcomeReason.LOW_RISK

    classify_report_result(result)

    assert result.outcome == ScanOutcome.SKIPPED
    assert result.outcome_reason == OutcomeReason.LOW_RISK
    assert result.risk_label == RiskLabel.SKIPPED
    assert result.report_category == ReportCategory.SKIPPED


def test_partial_payload_without_assessment_complete_stays_unknown() -> None:
    # A FOUND result with assessment_complete=False (partial/empty payload) must
    # stay Unknown — "Never imply safe."
    result = make_result(ClassificationBucket.HASH_ONLY, EngineState.FOUND)
    # assessment_complete defaults to False (no engine_stats supplied to make_result)
    result = classify_report_result(result)

    assert result.risk_label == RiskLabel.UNKNOWN
    assert result.report_category == ReportCategory.FULL_INVENTORY


def test_build_scan_report_records_engine_breakdown():
    from pathlib import Path

    from hscanner.report import build_scan_report, report_payload

    report = build_scan_report(
        Path("."), [], online=True, upload_consent=False,
        engine_id="combined", engine_name="Combined",
        engine_breakdown={"virustotal": 3, "metadefender": 1, "cache": 2},
    )
    assert report.engine_breakdown == {"virustotal": 3, "metadefender": 1, "cache": 2}
    assert report_payload(report)["engine_breakdown"] == {
        "virustotal": 3, "metadefender": 1, "cache": 2,
    }


def test_report_payload_records_request_metrics_by_engine():
    from hscanner.budget import RequestMetrics

    metrics = RequestMetrics(by_kind=(("lookup", 2),))
    report = build_scan_report(
        Path("."),
        [],
        online=True,
        upload_consent=False,
        engine_id="combined",
        engine_name="Combined",
        request_metrics_by_engine={"virustotal": metrics},
    )

    payload = report_payload(report)

    assert payload["request_metrics_by_engine"]["virustotal"]["total"] == 2
