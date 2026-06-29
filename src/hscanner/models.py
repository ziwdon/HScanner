from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from hscanner.errors import ErrorCode


class ClassificationBucket(StrEnum):
    SKIPPED = "skipped"
    HASH_ONLY = "hash_only"
    UPLOAD_CANDIDATE = "upload_candidate"
    SUSPICIOUS_UPLOAD_BLOCKED = "suspicious_upload_blocked"


class RiskTier(StrEnum):
    PRIORITY = "priority"
    LOW_RISK = "low_risk"
    SKIPPED = "skipped"


_PRIORITY_BUCKETS = {
    ClassificationBucket.UPLOAD_CANDIDATE,
    ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED,
}


def risk_tier_for(bucket: "ClassificationBucket") -> RiskTier:
    if bucket in _PRIORITY_BUCKETS:
        return RiskTier.PRIORITY
    if bucket == ClassificationBucket.SKIPPED:
        return RiskTier.SKIPPED
    return RiskTier.LOW_RISK


class RiskLabel(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NO_DETECTIONS = "no_detections"
    UNKNOWN = "unknown"
    SKIPPED = "skipped"


class ScanOutcome(StrEnum):
    INFECTED = "infected"
    NO_DETECTIONS = "no_detections"
    NEEDS_ATTENTION = "needs_attention"
    SKIPPED = "skipped"
    ERROR = "error"


class OutcomeReason(StrEnum):
    ENGINE_DETECTION = "engine_detection"
    ENGINE_CLEAN = "engine_clean"
    ENGINE_NOT_FOUND = "engine_not_found"
    INCOMPLETE_ENGINE_RESULT = "incomplete_engine_result"
    SCAN_INCOMPLETE = "scan_incomplete"
    UPLOAD_BLOCKED = "upload_blocked"
    LOW_RISK = "low_risk"
    SENSITIVE = "sensitive"
    UNSUPPORTED_FILE = "unsupported_file"


class LookupStatus(StrEnum):
    NOT_CHECKED = "not_checked"
    FOUND = "found"
    NOT_FOUND = "not_found"


class UploadStatus(StrEnum):
    NOT_UPLOADED = "not_uploaded"
    UPLOAD_FAILED = "upload_failed"
    UPLOADED = "uploaded"
    ANALYSIS_COMPLETE = "analysis_complete"
    ANALYSIS_FAILED = "analysis_failed"


class ReportCategory(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN_BUT_SUSPICIOUS = "unknown_but_suspicious"
    UPLOAD_BLOCKED = "upload_blocked"
    ERRORS = "errors"
    NO_DETECTIONS = "no_detections"
    SKIPPED = "skipped"
    FULL_INVENTORY = "full_inventory"


class EngineState(StrEnum):
    NOT_QUERIED = "not_queried"
    FOUND = "found"
    NOT_FOUND = "not_found"
    UPLOADED = "uploaded"
    ERROR = "error"


class ScanStatus(StrEnum):
    COMPLETED = "completed"
    KEY_MISSING = "key_missing"
    QUOTA_EXHAUSTED = "quota_exhausted"
    AUTH_FAILED = "auth_failed"
    CANCELLED = "cancelled"


class ReportAction(StrEnum):
    SKIPPED = "skipped"
    HASHED = "hashed"
    CACHE_HIT = "cache_hit"
    RESULT_REUSED = "result_reused"
    LOOKUP_FOUND = "lookup_found"
    LOOKUP_NOT_FOUND = "lookup_not_found"
    UPLOADED = "uploaded"
    ANALYSIS_COMPLETED = "analysis_completed"
    FAILED = "failed"


class AnalysisStatus(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


@dataclass(frozen=True)
class FileRecord:
    root: Path
    path: Path
    size: int
    mtime_ns: int
    mode: int
    is_symlink: bool
    is_regular: bool
    is_hidden: bool

    @property
    def relative_path(self) -> str:
        return self.path.relative_to(self.root).as_posix()


@dataclass
class Classification:
    bucket: ClassificationBucket
    reason: str
    upload_eligible: bool
    hash_eligible: bool
    suspicious: bool = False
    skip_reason: OutcomeReason | None = None


@dataclass
class FileResult:
    record: FileRecord
    classification: Classification
    sha256: str | None = None
    engine_id: str | None = None
    outcome: ScanOutcome = ScanOutcome.NEEDS_ATTENTION
    outcome_reason: OutcomeReason | ErrorCode = OutcomeReason.SCAN_INCOMPLETE
    lookup_status: LookupStatus = LookupStatus.NOT_CHECKED
    upload_status: UploadStatus = UploadStatus.NOT_UPLOADED
    engine_state: EngineState = EngineState.NOT_QUERIED
    risk_label: RiskLabel = RiskLabel.UNKNOWN
    report_category: ReportCategory = ReportCategory.FULL_INVENTORY
    permalink: str | None = None
    engine_stats: dict[str, int] = field(default_factory=dict)
    detections: list[dict[str, str]] = field(default_factory=list)
    errors: list[ErrorCode] = field(default_factory=list)
    raw_result: dict[str, Any] | None = None
    action: ReportAction = ReportAction.SKIPPED
    analysis_status: AnalysisStatus = AnalysisStatus.NOT_APPLICABLE
    assessment_complete: bool = False
    last_analysis_at: int | None = None
    executable_bit: bool = False
    shebang: bool = False
    elf: bool = False
