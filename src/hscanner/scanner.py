import asyncio
import sqlite3
from collections.abc import Callable, Iterable
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hscanner.budget import (
    BudgetExhausted,
    QuotaExhausted,
    QuotaStopReason,
    RequestKind,
    RequestMetrics,
)
from hscanner.cache import CachedEngineResult, EngineCache
from hscanner.classifier import classify_file, file_signals, reclassify_with_signals
from hscanner.engines.base import EngineFileReport
from hscanner.engines.rotation import EngineRotation, EngineSlot
from hscanner.errors import ErrorCode, HScannerError
from hscanner.hash import read_magic, sha256_file
from hscanner.inventory import InventoryPathError, iter_inventory, record_from_path
from hscanner.models import (
    AnalysisStatus,
    ClassificationBucket,
    EngineState,
    FileResult,
    LookupStatus,
    OutcomeReason,
    ReportAction,
    RiskTier,
    ScanOutcome,
    ScanStatus,
    UploadStatus,
    risk_tier_for,
)
from hscanner.policy.loader import load_default_policy
from hscanner.progress import (
    EventType,
    ScanCancelled,
    ScanController,
    ScanHooks,
    ScanObserver,
    ScanProgressEvent,
    ScanStage,
)
from hscanner.report import classify_report_result
from hscanner.state import ScanState
from hscanner.store import open_global_store


@dataclass
class OnlineScanOutcome:
    results: list[FileResult]
    status: ScanStatus = ScanStatus.COMPLETED
    quota_stop_reasons: tuple[QuotaStopReason, ...] = ()
    request_metrics: RequestMetrics = field(default_factory=RequestMetrics.zero)
    request_metrics_by_engine: dict[str, RequestMetrics] = field(default_factory=dict)
    engine_breakdown: dict[str, int] = field(default_factory=dict)


def single_engine_rotation(engine: Any, *, wait_threshold: float = 300.0) -> EngineRotation:
    """Wrap a single engine in a one-slot rotation (for single-engine callers)."""
    return EngineRotation([EngineSlot(engine)], wait_threshold=wait_threshold)


def _sum_metrics(metrics_list: Iterable[RequestMetrics]) -> RequestMetrics:
    totals = {kind.value: 0 for kind in RequestKind}
    pacing_count = 0
    pacing_seconds = 0.0
    rl_count = 0
    rl_seconds = 0.0
    for m in metrics_list:
        for kind, value in m.by_kind:
            totals[kind] = totals.get(kind, 0) + value
        pacing_count += m.pacing_wait_count
        pacing_seconds += m.pacing_wait_seconds
        rl_count += m.rate_limit_wait_count
        rl_seconds += m.rate_limit_wait_seconds
    return RequestMetrics(
        by_kind=tuple(totals.items()),
        pacing_wait_count=pacing_count,
        pacing_wait_seconds=pacing_seconds,
        rate_limit_wait_count=rl_count,
        rate_limit_wait_seconds=rl_seconds,
    )


def _engine_breakdown(results: Iterable[FileResult]) -> dict[str, int]:
    breakdown: dict[str, int] = {}
    for result in results:
        if result.action == ReportAction.CACHE_HIT:
            source = "cache"
        else:
            source = result.engine_id or "not_checked"
        breakdown[source] = breakdown.get(source, 0) + 1
    return breakdown


def _cache_lookup_any(
    cache: EngineCache, sha: str, active_id: str, all_ids: list[str]
) -> tuple[str | None, CachedEngineResult | None]:
    order = [active_id] + [eid for eid in all_ids if eid != active_id]
    for eid in order:
        try:
            cached = cache.get(eid, sha)
        except sqlite3.Error:
            cached = None  # cache read failure → miss; fall through to live lookup
        if cached is not None:
            return eid, cached
    return None, None


async def _resolve_with_engine(
    engine: Any,
    result: FileResult,
    sha: str,
    *,
    cache: EngineCache,
    engine_id: str,
    upload_consent: bool,
    engine_results: dict[str, tuple[EngineState, EngineFileReport | None, str]],
    observer: ScanObserver | None,
) -> None:
    """Run lookup/upload/poll on one engine.

    Pre-upload limit errors (from ``get_file_report``/``upload_file``) propagate so
    the caller can fail over to the next engine. Once ``upload_file`` succeeds the
    file is pinned to this engine: a poll failure is recorded on the result and
    swallowed (the file is NOT re-uploaded to another engine).
    """
    _emit(observer, ScanProgressEvent(
        type=EventType.STAGE_CHANGED,
        stage=ScanStage.LOOKUP,
        engine_id=engine_id,
    ))
    result.engine_id = engine_id
    result.upload_status = UploadStatus.NOT_UPLOADED
    report = await engine.get_file_report(sha)  # may raise -> failover
    if report is not None:
        result.lookup_status = LookupStatus.FOUND
        result.engine_state = EngineState.FOUND
        _apply_engine_report(result, report)
        engine_results[sha] = (EngineState.FOUND, report, engine_id)
        _cache_payload(cache, engine_id, sha, report)
        result.action = ReportAction.LOOKUP_FOUND
        return
    result.lookup_status = LookupStatus.NOT_FOUND
    result.engine_state = EngineState.NOT_FOUND
    result.action = ReportAction.LOOKUP_NOT_FOUND
    if not (upload_consent and result.classification.upload_eligible):
        engine_results[sha] = (EngineState.NOT_FOUND, None, engine_id)
        return
    _emit(observer, ScanProgressEvent(
        type=EventType.STAGE_CHANGED,
        stage=ScanStage.UPLOADING,
        engine_id=engine_id,
    ))
    try:
        analysis_id = await engine.upload_file(result.record.path)  # may raise -> failover
    except HScannerError:
        result.upload_status = UploadStatus.UPLOAD_FAILED
        raise
    result.upload_status = UploadStatus.UPLOADED
    result.action = ReportAction.UPLOADED
    try:  # post-upload: pinned to this engine
        _emit(observer, ScanProgressEvent(
            type=EventType.STAGE_CHANGED,
            stage=ScanStage.POLLING,
            engine_id=engine_id,
        ))
        report = await engine.wait_for_analysis(analysis_id, sha)
        result.action = ReportAction.ANALYSIS_COMPLETED
        result.upload_status = UploadStatus.ANALYSIS_COMPLETE
        result.analysis_status = AnalysisStatus.COMPLETED
        result.engine_state = EngineState.UPLOADED
        _apply_engine_report(result, report)
        engine_results[sha] = (EngineState.UPLOADED, report, engine_id)
        _cache_payload(cache, engine_id, sha, report)
    except HScannerError as exc:
        result.upload_status = UploadStatus.ANALYSIS_FAILED
        if exc.code == ErrorCode.ANALYSIS_TIMEOUT:
            result.analysis_status = AnalysisStatus.TIMED_OUT
        else:
            result.analysis_status = AnalysisStatus.FAILED
        result.engine_state = EngineState.ERROR
        result.errors.append(exc.code)


def run_local_scan(root: Path, *, scan_state: "ScanState | None" = None) -> list[FileResult]:
    policy = load_default_policy()
    results: list[FileResult] = []
    inode_hashes: dict[tuple[int, int], str] = {}
    for record in iter_inventory(root):
        classification = classify_file(record, policy)
        result = FileResult(record=record, classification=classification)
        if classification.hash_eligible and record.is_regular:
            try:
                stat = record.path.stat()
                inode_key = (stat.st_dev, stat.st_ino)
                cached = None
                if scan_state is not None:
                    cached = scan_state.cached_sha256(
                        record.relative_path, stat.st_size, stat.st_mtime_ns
                    )
                if cached is not None:
                    result.sha256 = cached
                elif inode_key in inode_hashes:
                    result.sha256 = inode_hashes[inode_key]
                else:
                    result.sha256 = sha256_file(record.path)
                    inode_hashes[inode_key] = result.sha256
                try:
                    prefix = read_magic(record.path)
                except OSError:
                    prefix = b""
                signals = file_signals(prefix, record.mode)
                result.executable_bit = signals["executable_bit"]
                result.elf = signals["elf"]
                result.shebang = signals["shebang"]
                promoted = reclassify_with_signals(record, classification, prefix, policy)
                if promoted is not classification:
                    classification = promoted
                    result.classification = promoted
                result.action = ReportAction.HASHED
                if scan_state is not None:
                    scan_state.record_file(
                        record.relative_path,
                        stat.st_size,
                        stat.st_mtime_ns,
                        result.sha256,
                        f"{stat.st_dev}:{stat.st_ino}",
                        "hashed",
                    )
            except PermissionError:
                result.errors.append(ErrorCode.PERMISSION_DENIED)
                result.action = ReportAction.FAILED
            except FileNotFoundError:
                result.errors.append(ErrorCode.FILE_VANISHED)
                result.action = ReportAction.FAILED
            except OSError:
                result.errors.append(ErrorCode.HASH_FAILED)
                result.action = ReportAction.FAILED
        results.append(classify_report_result(result))
    return results


def _emit(observer: "ScanObserver | None", event: ScanProgressEvent) -> None:
    if observer is not None:
        observer(event)


def _file_finished_event(index: int, result: FileResult) -> ScanProgressEvent:
    return ScanProgressEvent(
        type=EventType.FILE_FINISHED,
        index=index,
        report_category=result.report_category.value,
        risk_label=result.risk_label.value,
        engine_state=result.engine_state.value,
        had_error=bool(result.errors),
        action=result.action.value,
        engine_id=result.engine_id,
        outcome=result.outcome.value,
        outcome_reason=result.outcome_reason.value,
        lookup_status=result.lookup_status.value,
        upload_status=result.upload_status.value,
    )


def _apply_persisted_online_state(result: FileResult, state: dict[str, str]) -> bool:
    try:
        engine_state = EngineState(state["engine_state"])
        lookup_status = LookupStatus(state["lookup_status"])
        upload_status = UploadStatus(state["upload_status"])
    except (KeyError, ValueError):
        return False
    if engine_state != EngineState.NOT_FOUND or lookup_status != LookupStatus.NOT_FOUND:
        return False
    result.engine_id = state.get("engine_id")
    result.engine_state = engine_state
    result.lookup_status = lookup_status
    result.upload_status = upload_status
    result.action = ReportAction.RESULT_REUSED
    return True


def _record_persisted_online_state(scan_state: ScanState | None, result: FileResult) -> None:
    if scan_state is None or result.sha256 is None:
        return
    if (
        result.engine_state != EngineState.NOT_FOUND
        or result.lookup_status != LookupStatus.NOT_FOUND
    ):
        return
    try:
        stat = result.record.path.stat()
        scan_state.record_online_state(
            result.record.relative_path,
            stat.st_size,
            stat.st_mtime_ns,
            result.sha256,
            result.engine_id,
            result.engine_state.value,
            result.lookup_status.value,
            result.upload_status.value,
            result.action.value,
        )
    except (OSError, sqlite3.Error):
        pass


async def run_online_scan(
    root: Path,
    rotation: EngineRotation,
    upload_consent: bool,
    *,
    cache: EngineCache | None = None,
    scan_state: ScanState | None = None,
    refresh: bool = False,
    bypass_low_risk: bool = False,
    observer: ScanObserver | None = None,
    controller: ScanController | None = None,
) -> OnlineScanOutcome:
    if cache is None:
        cache = EngineCache(open_global_store())
    if observer is not None or controller is not None:
        hooks = ScanHooks(observer=observer, controller=controller)
        for slot in rotation._slots:
            if hasattr(slot.engine, "hooks"):
                slot.engine.hooks = hooks
    all_ids = [slot.engine.info.id for slot in rotation._slots]
    results = run_local_scan(root, scan_state=scan_state)
    results.sort(
        key=lambda r: (
            0 if risk_tier_for(r.classification.bucket) == RiskTier.PRIORITY else 1,
            r.record.relative_path,
        )
    )
    online_pending = sum(
        1 for r in results
        if r.sha256 and (
            not bypass_low_risk
            or risk_tier_for(r.classification.bucket) != RiskTier.LOW_RISK
        )
    )
    bypassed = sum(
        1 for r in results
        if r.sha256 and bypass_low_risk
        and risk_tier_for(r.classification.bucket) == RiskTier.LOW_RISK
    )
    _emit(observer, ScanProgressEvent(
        type=EventType.SCAN_STARTED, total=len(results),
        online_pending=online_pending, bypassed=bypassed,
    ))
    engine_results: dict[str, tuple[EngineState, EngineFileReport | None, str]] = {}
    status = ScanStatus.COMPLETED
    quota_stop_reasons: tuple[QuotaStopReason, ...] = ()
    finished_indices: set[int] = set()
    try:
        for index, result in enumerate(results):
            _emit(
                observer,
                ScanProgressEvent(
                    type=EventType.FILE_STARTED, index=index, path=result.record.relative_path
                ),
            )
            if controller is not None:
                await controller.checkpoint()
            try:
                if not result.sha256 or status != ScanStatus.COMPLETED:
                    continue
                if (
                    bypass_low_risk
                    and risk_tier_for(result.classification.bucket) == RiskTier.LOW_RISK
                ):
                    result.outcome = ScanOutcome.SKIPPED
                    result.outcome_reason = OutcomeReason.LOW_RISK
                    continue  # hashed locally; intentionally not checked against VirusTotal
                sha = result.sha256
                if not refresh and scan_state is not None:
                    try:
                        stat = result.record.path.stat()
                        persisted = scan_state.cached_online_state(
                            result.record.relative_path,
                            stat.st_size,
                            stat.st_mtime_ns,
                            sha,
                        )
                    except (OSError, sqlite3.Error):
                        persisted = None
                    if persisted is not None and _apply_persisted_online_state(result, persisted):
                        engine_results[sha] = (
                            EngineState.NOT_FOUND,
                            None,
                            result.engine_id or all_ids[0],
                        )
                        continue
                if sha in engine_results:
                    state, report, engine_id = engine_results[sha]
                    result.engine_id = engine_id
                    result.engine_state = state
                    result.lookup_status = (
                        LookupStatus.NOT_FOUND
                        if state in {EngineState.NOT_FOUND, EngineState.UPLOADED}
                        else LookupStatus.FOUND
                    )
                    if report is not None:
                        _apply_engine_report(result, report)
                    result.action = ReportAction.RESULT_REUSED
                    continue
                # Cross-engine cache reuse: a fresh hit on ANY engine serves the
                # file with zero live calls.
                if not refresh and all_ids:
                    eid, cached = _cache_lookup_any(cache, sha, all_ids[0], all_ids)
                    if cached is not None:
                        result.engine_id = eid
                        result.lookup_status = LookupStatus.FOUND
                        result.engine_state = EngineState.FOUND
                        _apply_engine_report(result, cached.report)
                        engine_results[sha] = (EngineState.FOUND, cached.report, eid)
                        result.action = ReportAction.CACHE_HIT
                        continue
                # Rotation-driven failover loop for this file.
                while True:
                    slot = rotation.next_available()
                    if slot is not None:
                        engine = slot.engine
                        engine_id = engine.info.id
                        try:
                            await _resolve_with_engine(
                                engine,
                                result,
                                sha,
                                cache=cache,
                                engine_id=engine_id,
                                upload_consent=upload_consent,
                                engine_results=engine_results,
                                observer=observer,
                            )
                        except QuotaExhausted as exc:
                            rotation.cool_quota(slot, exc.reasons)
                            continue
                        except BudgetExhausted:
                            rotation.cool(slot, seconds=float("inf"), reason="budget")
                            continue
                        except HScannerError as exc:
                            if exc.code == ErrorCode.ENGINE_RATE_LIMITED:
                                rotation.cool(
                                    slot,
                                    seconds=exc.retry_after or 60.0,
                                    reason="rate_limited",
                                )
                                continue
                            if exc.code == ErrorCode.ENGINE_AUTH_FAILED:
                                result.engine_id = engine_id
                                rotation.cool(slot, seconds=float("inf"), reason="auth")
                                continue
                            # Other pre-upload error: record on this file, no failover.
                            result.engine_id = engine_id
                            result.engine_state = EngineState.ERROR
                            result.errors.append(exc.code)
                            break
                        break
                    # No engine available right now.
                    wait = rotation.seconds_until_next()
                    if wait is None or wait > rotation.wait_threshold:
                        if rotation.all_cooled_for("auth"):
                            status = ScanStatus.AUTH_FAILED
                            result.engine_state = EngineState.ERROR
                            result.errors.append(ErrorCode.ENGINE_AUTH_FAILED)
                        elif rotation.all_cooled_for("budget"):
                            status = ScanStatus.QUOTA_EXHAUSTED
                            quota_stop_reasons = (QuotaStopReason.PER_SCAN,)
                        else:
                            status = ScanStatus.QUOTA_EXHAUSTED
                            cooled_reasons = rotation.cooled_reasons()
                            quota_stop_reasons = tuple(
                                reason
                                for reason in (
                                    QuotaStopReason.DAILY,
                                    QuotaStopReason.MONTHLY,
                                )
                                if reason.value in cooled_reasons
                            ) or (QuotaStopReason.DAILY,)
                        break
                    _emit(observer, ScanProgressEvent(
                        type=EventType.STAGE_CHANGED, stage=ScanStage.WAITING_RATE_LIMIT
                    ))
                    if controller is not None:
                        await controller.checkpoint()
                    await asyncio.sleep(wait)
                    # retry the same file with a (hopefully) available engine
            finally:
                _record_persisted_online_state(scan_state, result)
                classify_report_result(result)
                _emit(
                    observer,
                    _file_finished_event(index, result),
                )
                finished_indices.add(index)
    except ScanCancelled:
        status = ScanStatus.CANCELLED
    finalize_unchecked_results(results, bypass_low_risk=bypass_low_risk)
    for index, result in enumerate(results):
        if index not in finished_indices:
            _emit(observer, _file_finished_event(index, result))
    if scan_state is not None:
        if status == ScanStatus.COMPLETED:
            scan_state.mark_done()
        else:
            scan_state.mark_interrupted()
    _emit(observer, ScanProgressEvent(type=EventType.SCAN_FINISHED, status=status.value))
    by_engine = rotation.snapshots()
    return OnlineScanOutcome(
        results=results,
        status=status,
        quota_stop_reasons=quota_stop_reasons,
        request_metrics=_sum_metrics(by_engine.values()),
        request_metrics_by_engine=by_engine,
        engine_breakdown=_engine_breakdown(results),
    )


def finalize_unchecked_results(
    results: Iterable[FileResult], *, bypass_low_risk: bool
) -> None:
    """Finalize files that never received an engine lookup result."""
    for result in results:
        if (
            result.lookup_status == LookupStatus.NOT_CHECKED
            and result.classification.bucket != ClassificationBucket.SKIPPED
        ):
            if (
                bypass_low_risk
                and risk_tier_for(result.classification.bucket) == RiskTier.LOW_RISK
            ):
                result.outcome = ScanOutcome.SKIPPED
                result.outcome_reason = OutcomeReason.LOW_RISK
            else:
                result.outcome = ScanOutcome.NEEDS_ATTENTION
                result.outcome_reason = OutcomeReason.SCAN_INCOMPLETE
        classify_report_result(result)


def _cache_payload(cache: EngineCache, engine_id: str, sha: str, report: EngineFileReport) -> None:
    try:
        cache.put(
            CachedEngineResult(
                engine_id=engine_id,
                sha256=sha,
                fetched_at=datetime.now(UTC),
                last_analysis_at=report.last_analysis_at,
                report=report,
            )
        )
    except sqlite3.Error:
        pass  # cache write failure is non-fatal; the file still gets its VT verdict


class SingleFileNotEligible(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


async def scan_single_file(
    root: Path,
    relative_path: str,
    engine: Any,
    cache: EngineCache,
    *,
    policy: dict[str, Any] | None = None,
) -> FileResult:
    policy = policy or load_default_policy()
    try:
        record = record_from_path(root, relative_path)  # FileNotFoundError if vanished
    except InventoryPathError as exc:
        raise SingleFileNotEligible("invalid_path") from exc
    classification = classify_file(record, policy)
    if classification.bucket == ClassificationBucket.SKIPPED:
        reason = (
            classification.skip_reason.value
            if classification.skip_reason is not None
            else "not_eligible"
        )
        raise SingleFileNotEligible(reason)
    prefix = read_magic(record.path)
    signals = file_signals(prefix, record.mode)
    classification = reclassify_with_signals(record, classification, prefix, policy)
    if risk_tier_for(classification.bucket) != RiskTier.PRIORITY:
        raise SingleFileNotEligible("not_priority")
    if not classification.upload_eligible:
        raise SingleFileNotEligible("too_large")

    engine_id = engine.info.id
    result = FileResult(record=record, classification=classification)
    result.engine_id = engine_id
    result.executable_bit = signals["executable_bit"]
    result.elf = signals["elf"]
    result.shebang = signals["shebang"]
    result.sha256 = sha256_file(record.path)
    result.action = ReportAction.HASHED

    report = await engine.get_file_report(result.sha256)
    if report is not None:
        result.lookup_status = LookupStatus.FOUND
        result.engine_state = EngineState.FOUND
        _apply_engine_report(result, report)
        result.action = ReportAction.LOOKUP_FOUND
        _cache_payload(cache, engine_id, result.sha256, report)
        return classify_report_result(result)

    result.lookup_status = LookupStatus.NOT_FOUND
    try:
        analysis_id = await engine.upload_file(record.path)
    except HScannerError:
        result.upload_status = UploadStatus.UPLOAD_FAILED
        raise
    result.upload_status = UploadStatus.UPLOADED
    result.action = ReportAction.UPLOADED
    try:
        report = await engine.wait_for_analysis(analysis_id, result.sha256)
        result.action = ReportAction.ANALYSIS_COMPLETED
        result.upload_status = UploadStatus.ANALYSIS_COMPLETE
        result.analysis_status = AnalysisStatus.COMPLETED
        result.engine_state = EngineState.UPLOADED
        _apply_engine_report(result, report)
        _cache_payload(cache, engine_id, result.sha256, report)
    except HScannerError as exc:
        result.upload_status = UploadStatus.ANALYSIS_FAILED
        result.analysis_status = (
            AnalysisStatus.TIMED_OUT if exc.code == ErrorCode.ANALYSIS_TIMEOUT
            else AnalysisStatus.FAILED
        )
        result.engine_state = EngineState.ERROR
        result.errors.append(exc.code)
    return classify_report_result(result)


async def scan_single_file_with_rotation(
    root: Path,
    relative_path: str,
    rotation: EngineRotation,
    cache: EngineCache,
    *,
    policy: dict[str, Any] | None = None,
    state_callback: Callable[[str, str | None], None] | None = None,
) -> FileResult:
    policy = policy or load_default_policy()
    try:
        record = record_from_path(root, relative_path)
    except InventoryPathError as exc:
        raise SingleFileNotEligible("invalid_path") from exc
    classification = classify_file(record, policy)
    if classification.bucket == ClassificationBucket.SKIPPED:
        reason = (
            classification.skip_reason.value
            if classification.skip_reason is not None
            else "not_eligible"
        )
        raise SingleFileNotEligible(reason)
    prefix = read_magic(record.path)
    signals = file_signals(prefix, record.mode)
    classification = reclassify_with_signals(record, classification, prefix, policy)
    if risk_tier_for(classification.bucket) != RiskTier.PRIORITY:
        raise SingleFileNotEligible("not_priority")
    if not classification.upload_eligible:
        raise SingleFileNotEligible("too_large")

    result = FileResult(record=record, classification=classification)
    result.executable_bit = signals["executable_bit"]
    result.elf = signals["elf"]
    result.shebang = signals["shebang"]
    result.sha256 = sha256_file(record.path)
    result.action = ReportAction.HASHED
    engine_results: dict[str, tuple[EngineState, EngineFileReport | None, str]] = {}

    def observer(event: ScanProgressEvent) -> None:
        if (
            state_callback is not None
            and event.type == EventType.STAGE_CHANGED
            and event.stage is not None
        ):
            state_callback(str(event.stage), event.engine_id)

    while True:
        slot = rotation.next_available()
        if slot is not None:
            engine_id = slot.engine.info.id
            try:
                await _resolve_with_engine(
                    slot.engine,
                    result,
                    result.sha256,
                    cache=cache,
                    engine_id=engine_id,
                    upload_consent=True,
                    engine_results=engine_results,
                    observer=observer,
                )
            except QuotaExhausted as exc:
                rotation.cool_quota(slot, exc.reasons)
                continue
            except BudgetExhausted:
                rotation.cool(slot, seconds=float("inf"), reason="budget")
                continue
            except HScannerError as exc:
                if exc.code == ErrorCode.ENGINE_RATE_LIMITED:
                    rotation.cool(
                        slot,
                        seconds=exc.retry_after or 60.0,
                        reason="rate_limited",
                    )
                    continue
                if exc.code == ErrorCode.ENGINE_AUTH_FAILED:
                    result.engine_id = engine_id
                    rotation.cool(slot, seconds=float("inf"), reason="auth")
                    continue
                result.engine_id = engine_id
                result.engine_state = EngineState.ERROR
                result.errors.append(exc.code)
            return classify_report_result(result)

        wait = rotation.seconds_until_next()
        if wait is None or wait > rotation.wait_threshold:
            if rotation.all_cooled_for("auth"):
                result.errors.append(ErrorCode.ENGINE_AUTH_FAILED)
            elif rotation.all_cooled_for("budget"):
                result.errors.append(ErrorCode.ENGINE_QUOTA_EXHAUSTED)
            elif rotation.cooled_reasons():
                result.errors.append(ErrorCode.ENGINE_RATE_LIMITED)
            else:
                result.errors.append(ErrorCode.ENGINE_CLIENT_ERROR)
            result.engine_state = EngineState.ERROR
            return classify_report_result(result)
        if state_callback is not None:
            state_callback("waiting", None)
        await asyncio.sleep(wait)


def _apply_engine_report(result: FileResult, report: EngineFileReport) -> None:
    result.raw_result = deepcopy(report.raw)
    result.assessment_complete = report.assessment_complete
    result.engine_stats = dict(report.engine_stats)
    result.detections = [dict(detection) for detection in report.detections]
    result.permalink = report.permalink
    result.last_analysis_at = report.last_analysis_at
