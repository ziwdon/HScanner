import json
import secrets
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hscanner.budget import QuotaStopReason, RequestMetrics
from hscanner.models import (
    ClassificationBucket,
    EngineState,
    FileResult,
    LookupStatus,
    OutcomeReason,
    ReportAction,
    ReportCategory,
    RiskLabel,
    ScanOutcome,
    ScanStatus,
    UploadStatus,
)


def classify_report_result(result: FileResult) -> FileResult:
    """Set ``risk_label`` and ``report_category`` on ``result`` from its bucket,
    VT state, and VT stats. Mutates and returns the same object. Call this on
    every FileResult before passing results to ``cli_exit_code``."""
    if result.errors:
        result.outcome = ScanOutcome.ERROR
        result.outcome_reason = result.errors[0]
        result.risk_label = RiskLabel.UNKNOWN
        result.report_category = ReportCategory.ERRORS
        return result

    bucket = result.classification.bucket
    if bucket == ClassificationBucket.SKIPPED:
        result.outcome = ScanOutcome.SKIPPED
        result.outcome_reason = (
            result.classification.skip_reason or OutcomeReason.LOW_RISK
        )
        result.risk_label = RiskLabel.SKIPPED
        result.report_category = ReportCategory.SKIPPED
    else:
        malicious = result.engine_stats.get("malicious", 0)
        suspicious = result.engine_stats.get("suspicious", 0)
        if malicious > 0 or suspicious > 0 or result.detections:
            result.outcome = ScanOutcome.INFECTED
            result.outcome_reason = OutcomeReason.ENGINE_DETECTION
        elif (
            result.assessment_complete
            and result.lookup_status in {LookupStatus.FOUND, LookupStatus.NOT_FOUND}
        ):
            result.outcome = ScanOutcome.NO_DETECTIONS
            result.outcome_reason = OutcomeReason.ENGINE_CLEAN
        elif result.lookup_status == LookupStatus.NOT_FOUND:
            result.outcome = ScanOutcome.NEEDS_ATTENTION
            result.outcome_reason = (
                OutcomeReason.UPLOAD_BLOCKED
                if result.classification.suspicious
                and not result.classification.upload_eligible
                else OutcomeReason.ENGINE_NOT_FOUND
            )
        elif result.lookup_status == LookupStatus.FOUND:
            result.outcome = ScanOutcome.NEEDS_ATTENTION
            result.outcome_reason = OutcomeReason.INCOMPLETE_ENGINE_RESULT
        elif result.outcome_reason == OutcomeReason.LOW_RISK:
            result.outcome = ScanOutcome.SKIPPED
        else:
            result.outcome = ScanOutcome.NEEDS_ATTENTION
            result.outcome_reason = OutcomeReason.SCAN_INCOMPLETE
        if malicious >= 3:
            result.risk_label = RiskLabel.HIGH
            result.report_category = ReportCategory.HIGH
        elif malicious in {1, 2} or suspicious >= 2:
            result.risk_label = RiskLabel.MEDIUM
            result.report_category = ReportCategory.MEDIUM
        elif bucket == ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED:
            result.risk_label = RiskLabel.MEDIUM
            result.report_category = ReportCategory.UPLOAD_BLOCKED
        elif malicious == 0 and suspicious == 1:
            result.risk_label = RiskLabel.LOW
            result.report_category = ReportCategory.LOW
        elif bucket == ClassificationBucket.UPLOAD_CANDIDATE and result.engine_state in {
            EngineState.NOT_FOUND,
            EngineState.NOT_QUERIED,
        }:
            result.risk_label = RiskLabel.UNKNOWN
            result.report_category = ReportCategory.UNKNOWN_BUT_SUSPICIOUS
        elif (
            result.assessment_complete
            and malicious == 0
            and suspicious == 0
            and result.engine_state in {EngineState.FOUND, EngineState.UPLOADED}
        ):
            result.risk_label = RiskLabel.NO_DETECTIONS
            result.report_category = ReportCategory.NO_DETECTIONS
        else:
            result.risk_label = RiskLabel.UNKNOWN
            result.report_category = ReportCategory.FULL_INVENTORY
    return result


# ---------------------------------------------------------------------------
# Canonical frozen report types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DetectionRatio:
    flagged: int
    total: int


@dataclass(frozen=True)
class ReportFile:
    index: int
    relative_path: str
    size: int
    sha256: str | None
    classification_bucket: str
    classification_reason: str
    hash_eligible: bool
    upload_eligible: bool
    suspicious: bool
    outcome: str
    outcome_reason: str
    lookup_status: str
    upload_status: str
    risk_label: str
    report_category: str
    action: str
    engine_state: str
    permalink: str | None
    engine_counts: tuple[tuple[str, int], ...]
    detection_ratio: DetectionRatio
    detections: tuple[tuple[str, str, str], ...]
    last_analysis_at: str | None
    analysis_status: str
    errors: tuple[str, ...]
    json_reference: str
    raw_result: dict[str, Any] | None
    assessment_complete: bool
    executable_bit: bool
    shebang: bool
    elf: bool
    engine_id: str | None = None

    @property
    def engine_checked(self) -> bool:
        return self.lookup_status != LookupStatus.NOT_CHECKED.value


@dataclass(frozen=True)
class ReportSummary:
    inventoried: int
    scanned: int
    infected: int
    needs_attention: int
    hashed: int
    known_to_vt: int
    uploaded: int
    skipped: int
    upload_blocked: int
    detections: int
    unknown: int
    errors: int
    delay_count: int


@dataclass(frozen=True)
class ScanReport:
    schema_version: int
    report_id: str
    engine_id: str
    engine_name: str
    root: str
    generated_at: str
    online: bool
    upload_consent: bool
    status: str
    quota_stop_reasons: tuple[str, ...]
    request_metrics: RequestMetrics
    summary: ReportSummary
    files: tuple[ReportFile, ...]
    engine_breakdown: dict[str, int] = field(default_factory=dict)
    request_metrics_by_engine: dict[str, RequestMetrics] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _last_analysis_at(result: FileResult) -> str | None:
    value = result.last_analysis_at
    if type(value) is int:
        return datetime.fromtimestamp(value, UTC).isoformat().replace("+00:00", "Z")
    return None


def _report_file(index: int, result: FileResult) -> ReportFile:
    counts = tuple(sorted(result.engine_stats.items()))
    flagged = result.engine_stats.get("malicious", 0) + result.engine_stats.get("suspicious", 0)
    total = sum(value for _, value in counts)
    detections = tuple(
        sorted(
            (
                detection["engine"],
                detection["category"],
                detection["name"],
            )
            for detection in result.detections
        )
    )
    return ReportFile(
        index=index,
        relative_path=result.record.relative_path,
        size=result.record.size,
        sha256=result.sha256,
        classification_bucket=result.classification.bucket.value,
        classification_reason=result.classification.reason,
        hash_eligible=result.classification.hash_eligible,
        upload_eligible=result.classification.upload_eligible,
        suspicious=result.classification.suspicious,
        outcome=result.outcome.value,
        outcome_reason=result.outcome_reason.value,
        lookup_status=result.lookup_status.value,
        upload_status=result.upload_status.value,
        risk_label=result.risk_label.value,
        report_category=result.report_category.value,
        action=result.action.value,
        engine_state=result.engine_state.value,
        permalink=result.permalink,
        engine_counts=counts,
        detection_ratio=DetectionRatio(flagged=flagged, total=total),
        detections=detections,
        last_analysis_at=_last_analysis_at(result),
        analysis_status=result.analysis_status.value,
        errors=tuple(error.value for error in result.errors),
        json_reference=f"/files/{index}/raw_result",
        raw_result=deepcopy(result.raw_result),
        assessment_complete=result.assessment_complete,
        executable_bit=result.executable_bit,
        shebang=result.shebang,
        elf=result.elf,
        engine_id=result.engine_id,
    )


def _report_file_payload(file: ReportFile) -> dict[str, Any]:
    return {
        "index": file.index,
        "relative_path": file.relative_path,
        "size": file.size,
        "sha256": file.sha256,
        "classification_bucket": file.classification_bucket,
        "classification_reason": file.classification_reason,
        "hash_eligible": file.hash_eligible,
        "upload_eligible": file.upload_eligible,
        "suspicious": file.suspicious,
        "outcome": file.outcome,
        "outcome_reason": file.outcome_reason,
        "lookup_status": file.lookup_status,
        "upload_status": file.upload_status,
        "engine_checked": file.engine_checked,
        "permalink": file.permalink,
        "engine_counts": dict(file.engine_counts),
        "detection_ratio": {
            "flagged": file.detection_ratio.flagged,
            "total": file.detection_ratio.total,
        },
        "detections": [
            {"engine": engine, "category": category, "name": name}
            for engine, category, name in file.detections
        ],
        "last_analysis_at": file.last_analysis_at,
        "analysis_status": file.analysis_status,
        "errors": list(file.errors),
        "json_reference": file.json_reference,
        "raw_result": file.raw_result,
        "assessment_complete": file.assessment_complete,
        "executable_bit": file.executable_bit,
        "shebang": file.shebang,
        "elf": file.elf,
        "engine_id": file.engine_id,
    }


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def compute_summary(files: tuple[ReportFile, ...], metrics: RequestMetrics) -> ReportSummary:
    return ReportSummary(
        inventoried=len(files),
        scanned=sum(file.engine_checked for file in files),
        infected=sum(file.outcome == ScanOutcome.INFECTED.value for file in files),
        needs_attention=sum(
            file.outcome == ScanOutcome.NEEDS_ATTENTION.value for file in files
        ),
        hashed=sum(file.sha256 is not None for file in files),
        known_to_vt=sum(
            file.engine_state in {EngineState.FOUND.value, EngineState.UPLOADED.value}
            and file.assessment_complete
            for file in files
        ),
        uploaded=sum(
            file.upload_status in {
                UploadStatus.UPLOADED.value,
                UploadStatus.ANALYSIS_COMPLETE.value,
                UploadStatus.ANALYSIS_FAILED.value,
            }
            for file in files
        ),
        skipped=sum(
            file.outcome == ScanOutcome.SKIPPED.value for file in files
        ),
        upload_blocked=sum(
            file.classification_bucket == ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED.value
            for file in files
        ),
        detections=sum(file.detection_ratio.flagged > 0 for file in files),
        unknown=sum(
            file.report_category
            in {ReportCategory.UNKNOWN_BUT_SUSPICIOUS.value, ReportCategory.FULL_INVENTORY.value}
            for file in files
        ),
        errors=sum(file.outcome == ScanOutcome.ERROR.value for file in files),
        delay_count=metrics.pacing_wait_count + metrics.rate_limit_wait_count,
    )


def build_scan_report(
    root: Path,
    results: list[FileResult],
    *,
    online: bool,
    upload_consent: bool,
    engine_id: str = "virustotal",
    engine_name: str = "VirusTotal",
    status: ScanStatus = ScanStatus.COMPLETED,
    quota_stop_reasons: tuple[QuotaStopReason, ...] = (),
    request_metrics: RequestMetrics | None = None,
    report_id_factory: Callable[[], str] = lambda: secrets.token_urlsafe(24),
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    engine_breakdown: dict[str, int] | None = None,
    request_metrics_by_engine: dict[str, RequestMetrics] | None = None,
) -> ScanReport:
    metrics = request_metrics or RequestMetrics.zero()
    ordered = sorted(results, key=lambda result: result.record.relative_path)
    files = tuple(_report_file(index, result) for index, result in enumerate(ordered))
    summary = compute_summary(files, metrics)
    generated = now().astimezone(UTC).isoformat().replace("+00:00", "Z")
    return ScanReport(
        schema_version=3,
        report_id=report_id_factory(),
        engine_id=engine_id,
        engine_name=engine_name,
        root=str(root.resolve()),
        generated_at=generated,
        online=online,
        upload_consent=upload_consent,
        status=status.value,
        quota_stop_reasons=tuple(reason.value for reason in quota_stop_reasons),
        request_metrics=metrics,
        summary=summary,
        files=files,
        engine_breakdown=dict(engine_breakdown or {}),
        request_metrics_by_engine=dict(request_metrics_by_engine or {}),
    )


# ---------------------------------------------------------------------------
# Serializers
# ---------------------------------------------------------------------------


def report_payload(report: ScanReport) -> dict[str, Any]:
    """Return a versioned JSON-serializable dict for a ScanReport.

    Does NOT include the API key or any secret. Suitable for CLI --json output
    and for ``export_report_json``."""
    metrics = report.request_metrics
    summary = report.summary

    def metrics_payload(value: RequestMetrics) -> dict[str, Any]:
        return {
            "total": value.total,
            "by_kind": dict(value.by_kind),
            "pacing_wait_count": value.pacing_wait_count,
            "pacing_wait_seconds": value.pacing_wait_seconds,
            "rate_limit_wait_count": value.rate_limit_wait_count,
            "rate_limit_wait_seconds": value.rate_limit_wait_seconds,
        }

    return {
        "schema_version": report.schema_version,
        "report_id": report.report_id,
        "engine_id": report.engine_id,
        "engine_name": report.engine_name,
        "engine_breakdown": dict(report.engine_breakdown),
        "root": report.root,
        "generated_at": report.generated_at,
        "online": report.online,
        "upload_consent": report.upload_consent,
        "status": report.status,
        "quota_stop_reasons": list(report.quota_stop_reasons),
        "request_metrics": metrics_payload(metrics),
        "request_metrics_by_engine": {
            engine_id: metrics_payload(engine_metrics)
            for engine_id, engine_metrics in report.request_metrics_by_engine.items()
        },
        "summary": {
            "inventoried": summary.inventoried,
            "scanned": summary.scanned,
            "infected": summary.infected,
            "needs_attention": summary.needs_attention,
            "uploaded": summary.uploaded,
            "skipped": summary.skipped,
            "errors": summary.errors,
            "delay_count": summary.delay_count,
        },
        "files": [_report_file_payload(file) for file in report.files],
    }


def _metrics_from_payload(payload: dict[str, Any] | None) -> RequestMetrics:
    payload = payload or {}
    by_kind = payload.get("by_kind") or {}
    return RequestMetrics(
        by_kind=tuple((str(kind), int(count)) for kind, count in by_kind.items()),
        pacing_wait_count=int(payload.get("pacing_wait_count") or 0),
        pacing_wait_seconds=float(payload.get("pacing_wait_seconds") or 0.0),
        rate_limit_wait_count=int(payload.get("rate_limit_wait_count") or 0),
        rate_limit_wait_seconds=float(payload.get("rate_limit_wait_seconds") or 0.0),
    )


def _engine_state_from_payload(file: dict[str, Any]) -> str:
    if file.get("upload_status") in {
        UploadStatus.UPLOADED.value,
        UploadStatus.ANALYSIS_COMPLETE.value,
        UploadStatus.ANALYSIS_FAILED.value,
    }:
        return EngineState.UPLOADED.value
    if file.get("lookup_status") == LookupStatus.FOUND.value:
        return EngineState.FOUND.value
    if file.get("lookup_status") == LookupStatus.NOT_FOUND.value:
        return EngineState.NOT_FOUND.value
    return EngineState.NOT_QUERIED.value


def _report_category_from_payload(file: dict[str, Any]) -> str:
    outcome = file.get("outcome")
    reason = file.get("outcome_reason")
    if outcome == ScanOutcome.INFECTED.value:
        return ReportCategory.HIGH.value
    if outcome == ScanOutcome.NO_DETECTIONS.value:
        return ReportCategory.NO_DETECTIONS.value
    if outcome == ScanOutcome.SKIPPED.value:
        return ReportCategory.SKIPPED.value
    if outcome == ScanOutcome.ERROR.value:
        return ReportCategory.ERRORS.value
    if reason == OutcomeReason.UPLOAD_BLOCKED.value:
        return ReportCategory.UPLOAD_BLOCKED.value
    if file.get("classification_bucket") == ClassificationBucket.UPLOAD_CANDIDATE.value:
        return ReportCategory.UNKNOWN_BUT_SUSPICIOUS.value
    return ReportCategory.FULL_INVENTORY.value


def _risk_label_from_payload(file: dict[str, Any]) -> str:
    outcome = file.get("outcome")
    if outcome == ScanOutcome.NO_DETECTIONS.value:
        return RiskLabel.NO_DETECTIONS.value
    if outcome == ScanOutcome.SKIPPED.value:
        return RiskLabel.SKIPPED.value
    if outcome == ScanOutcome.INFECTED.value:
        flagged = (file.get("detection_ratio") or {}).get("flagged") or 0
        return RiskLabel.HIGH.value if flagged >= 3 else RiskLabel.MEDIUM.value
    return RiskLabel.UNKNOWN.value


def _action_from_payload(file: dict[str, Any]) -> str:
    if file.get("outcome") == ScanOutcome.SKIPPED.value:
        return ReportAction.SKIPPED.value
    if file.get("upload_status") == UploadStatus.ANALYSIS_COMPLETE.value:
        return ReportAction.ANALYSIS_COMPLETED.value
    if file.get("upload_status") == UploadStatus.UPLOADED.value:
        return ReportAction.UPLOADED.value
    if file.get("lookup_status") == LookupStatus.FOUND.value:
        return ReportAction.LOOKUP_FOUND.value
    if file.get("lookup_status") == LookupStatus.NOT_FOUND.value:
        return ReportAction.LOOKUP_NOT_FOUND.value
    return ReportAction.HASHED.value if file.get("sha256") else ReportAction.SKIPPED.value


def _report_file_from_payload(file: dict[str, Any]) -> ReportFile:
    ratio = file.get("detection_ratio") or {}
    detections = tuple(
        sorted(
            (
                str(detection.get("engine", "")),
                str(detection.get("category", "")),
                str(detection.get("name", "")),
            )
            for detection in file.get("detections", [])
            if isinstance(detection, dict)
        )
    )
    return ReportFile(
        index=int(file["index"]),
        relative_path=str(file["relative_path"]),
        size=int(file["size"]),
        sha256=file.get("sha256"),
        classification_bucket=str(file["classification_bucket"]),
        classification_reason=str(file["classification_reason"]),
        hash_eligible=bool(file["hash_eligible"]),
        upload_eligible=bool(file["upload_eligible"]),
        suspicious=bool(file["suspicious"]),
        outcome=str(file["outcome"]),
        outcome_reason=str(file["outcome_reason"]),
        lookup_status=str(file["lookup_status"]),
        upload_status=str(file["upload_status"]),
        risk_label=_risk_label_from_payload(file),
        report_category=_report_category_from_payload(file),
        action=_action_from_payload(file),
        engine_state=_engine_state_from_payload(file),
        permalink=file.get("permalink"),
        engine_counts=tuple(
            sorted((str(kind), int(count)) for kind, count in file.get("engine_counts", {}).items())
        ),
        detection_ratio=DetectionRatio(
            flagged=int(ratio.get("flagged") or 0),
            total=int(ratio.get("total") or 0),
        ),
        detections=detections,
        last_analysis_at=file.get("last_analysis_at"),
        analysis_status=str(file["analysis_status"]),
        errors=tuple(str(error) for error in file.get("errors", [])),
        json_reference=str(file["json_reference"]),
        raw_result=deepcopy(file.get("raw_result")),
        assessment_complete=bool(file["assessment_complete"]),
        executable_bit=bool(file["executable_bit"]),
        shebang=bool(file["shebang"]),
        elf=bool(file["elf"]),
        engine_id=file.get("engine_id"),
    )


def scan_report_from_payload(payload: dict[str, Any]) -> ScanReport:
    """Restore a ``ScanReport`` from the public schema-v3 JSON payload."""
    metrics = _metrics_from_payload(payload.get("request_metrics"))
    files = tuple(_report_file_from_payload(file) for file in payload.get("files", []))
    return ScanReport(
        schema_version=int(payload["schema_version"]),
        report_id=str(payload["report_id"]),
        engine_id=str(payload.get("engine_id") or "virustotal"),
        engine_name=str(payload.get("engine_name") or "VirusTotal"),
        root=str(payload["root"]),
        generated_at=str(payload["generated_at"]),
        online=bool(payload["online"]),
        upload_consent=bool(payload["upload_consent"]),
        status=str(payload["status"]),
        quota_stop_reasons=tuple(str(reason) for reason in payload.get("quota_stop_reasons", [])),
        request_metrics=metrics,
        summary=compute_summary(files, metrics),
        files=files,
        engine_breakdown=dict(payload.get("engine_breakdown") or {}),
        request_metrics_by_engine={
            str(engine_id): _metrics_from_payload(engine_metrics)
            for engine_id, engine_metrics in (
                payload.get("request_metrics_by_engine") or {}
            ).items()
        },
    )


def export_report_json(results: list[FileResult], output: Path) -> None:
    """Write the scan results to *output* as indented JSON using the canonical schema.

    Delegates to ``build_scan_report`` + ``report_payload`` — no field list duplication,
    no secrets. Root is derived from the first result's record."""
    root = results[0].record.root if results else Path("/")
    report = build_scan_report(root, results, online=False, upload_consent=False)
    output.write_text(
        json.dumps(report_payload(report), indent=2, sort_keys=True), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Exit code
# ---------------------------------------------------------------------------


def cli_exit_code(
    report: ScanReport,
    *,
    fatal: bool = False,
    config_error: bool = False,
) -> int:
    """Return the deterministic CLI exit code for a ScanReport.

    Precedence: fatal=6, config_error=3, key_missing/auth_failed=4,
    quota_exhausted=5, any per-file errors=2, any attention category=1, else 0."""
    if fatal:
        return 6
    if config_error:
        return 3
    if report.status in {ScanStatus.KEY_MISSING.value, ScanStatus.AUTH_FAILED.value}:
        return 4
    if report.status == ScanStatus.QUOTA_EXHAUSTED.value:
        return 5
    if report.summary.errors:
        return 2
    if report.summary.infected or report.summary.needs_attention:
        return 1
    return 0
