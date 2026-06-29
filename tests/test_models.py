from pathlib import Path

from hscanner.errors import ErrorCode
from hscanner.models import (
    ClassificationBucket,
    EngineState,
    FileRecord,
    LookupStatus,
    OutcomeReason,
    ReportCategory,
    RiskLabel,
    ScanOutcome,
    UploadStatus,
)


def test_file_record_relative_path_is_posix() -> None:
    record = FileRecord(
        root=Path("/scan"),
        path=Path("/scan/sub/file.sh"),
        size=12,
        mtime_ns=100,
        mode=0o100755,
        is_symlink=False,
        is_regular=True,
        is_hidden=False,
    )

    assert record.relative_path == "sub/file.sh"


def test_stable_enum_values() -> None:
    assert ClassificationBucket.UPLOAD_CANDIDATE.value == "upload_candidate"
    assert RiskLabel.UNKNOWN.value == "unknown"
    assert ReportCategory.UNKNOWN_BUT_SUSPICIOUS.value == "unknown_but_suspicious"
    assert EngineState.NOT_FOUND.value == "not_found"
    assert ErrorCode.ENGINE_AUTH_FAILED.value == "engine_auth_failed"


def test_outcome_state_values_are_stable() -> None:
    assert ScanOutcome.INFECTED.value == "infected"
    assert OutcomeReason.LOW_RISK.value == "low_risk"
    assert LookupStatus.NOT_CHECKED.value == "not_checked"
    assert UploadStatus.ANALYSIS_FAILED.value == "analysis_failed"


def test_file_result_engine_id_defaults_none():
    from pathlib import Path

    from hscanner.models import Classification, ClassificationBucket, FileRecord, FileResult

    record = FileRecord(
        root=Path("/r"), path=Path("/r/a"), size=1, mtime_ns=0, mode=0o644,
        is_symlink=False, is_regular=True, is_hidden=False,
    )
    cls = Classification(
        bucket=ClassificationBucket.UPLOAD_CANDIDATE, reason="x",
        upload_eligible=True, hash_eligible=True,
    )
    result = FileResult(record=record, classification=cls)
    assert result.engine_id is None
    result.engine_id = "metadefender"
    assert result.engine_id == "metadefender"
