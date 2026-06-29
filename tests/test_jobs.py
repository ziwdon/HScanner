# tests/test_jobs.py
import asyncio

import pytest

from hscanner.models import ScanStatus
from hscanner.progress import EventType, ScanProgressEvent, ScanStage
from hscanner.scanner import OnlineScanOutcome
from hscanner.web.jobs import JobBusy, JobManager, JobSnapshot, JobStatus, ScanJob


def test_snapshot_tracks_counts_and_current():
    job = ScanJob("id1", per_minute=4)
    job(ScanProgressEvent(type=EventType.SCAN_STARTED, total=3))
    job(ScanProgressEvent(type=EventType.FILE_STARTED, index=0, path="a.sh"))
    job(ScanProgressEvent(type=EventType.STAGE_CHANGED, stage=ScanStage.LOOKUP))
    job(ScanProgressEvent(type=EventType.FILE_FINISHED, index=0, report_category="no_detections",
                          risk_label="no_detections", engine_state="found", had_error=False))
    snap = job.snapshot.to_dict()
    assert snap["total"] == 3
    assert snap["processed"] == 1
    assert snap["current_path"] == "a.sh"
    assert job.snapshot.no_detections == 1


def test_snapshot_tracks_outcome_metrics():
    snap = JobSnapshot(per_minute=4)
    snap.apply(ScanProgressEvent(type=EventType.SCAN_STARTED, total=2))
    snap.apply(ScanProgressEvent(
        type=EventType.FILE_FINISHED,
        outcome="infected",
        outcome_reason="engine_detection",
        lookup_status="found",
        upload_status="analysis_complete",
    ))
    snap.apply(ScanProgressEvent(
        type=EventType.FILE_FINISHED,
        outcome="skipped",
        outcome_reason="low_risk",
        lookup_status="not_checked",
        upload_status="not_uploaded",
    ))

    payload = snap.to_dict()
    assert payload["scanned"] == 1
    assert payload["infected"] == 1
    assert payload["needs_attention"] == 0
    assert payload["uploaded"] == 1
    assert payload["skipped"] == 1
    assert "attention" not in payload
    assert "unknown" not in payload
    assert "no_detections" not in payload


def test_snapshot_retains_current_engine_id():
    snap = JobSnapshot(per_minute=4)
    snap.apply(ScanProgressEvent(
        type=EventType.STAGE_CHANGED,
        stage=ScanStage.LOOKUP,
        engine_id="virustotal",
    ))
    assert snap.to_dict()["current_engine_id"] == "virustotal"

    snap.apply(ScanProgressEvent(
        type=EventType.STAGE_CHANGED,
        stage=ScanStage.WAITING_RATE_LIMIT,
    ))
    assert snap.to_dict()["current_engine_id"] == "virustotal"

    snap.apply(ScanProgressEvent(
        type=EventType.STAGE_CHANGED,
        stage=ScanStage.LOOKUP,
        engine_id="metadefender",
    ))
    assert snap.to_dict()["current_engine_id"] == "metadefender"


def test_broadcast_fans_out_to_each_subscriber():
    job = ScanJob("id2", per_minute=4)
    q1 = job.subscribe()
    q2 = job.subscribe()
    event = ScanProgressEvent(type=EventType.FILE_STARTED, index=0, path="x")
    job(event)
    assert q1.get_nowait() == event
    assert q2.get_nowait() == event


def test_full_subscriber_queue_drops_without_error():
    job = ScanJob("id3", per_minute=4, queue_maxsize=1)
    q = job.subscribe()
    job(ScanProgressEvent(type=EventType.FILE_STARTED, index=0, path="a"))
    job(ScanProgressEvent(type=EventType.FILE_STARTED, index=1, path="b"))  # dropped, no raise
    assert q.qsize() == 1


async def test_manager_runs_job_to_finished_and_stores_report():
    manager = JobManager()

    async def factory(observer, controller):
        observer(ScanProgressEvent(type=EventType.SCAN_STARTED, total=1))
        observer(ScanProgressEvent(type=EventType.SCAN_FINISHED, status=ScanStatus.COMPLETED.value))
        return OnlineScanOutcome(results=[], status=ScanStatus.COMPLETED)

    def finalize(outcome):
        return "report-xyz"

    job = manager.start(factory, finalize, per_minute=4)
    await job.task
    assert job.status == JobStatus.FINISHED
    assert job.report_id == "report-xyz"
    assert manager.get(job.id) is job


async def test_manager_refuses_second_active_job():
    manager = JobManager()
    release = asyncio.Event()

    async def factory(observer, controller):
        await release.wait()
        return OnlineScanOutcome(results=[], status=ScanStatus.COMPLETED)

    job = manager.start(factory, lambda o: "r", per_minute=4)
    with pytest.raises(JobBusy):
        manager.start(factory, lambda o: "r", per_minute=4)
    release.set()
    await job.task


async def test_manager_maps_cancelled_and_error():
    manager = JobManager()

    async def cancel_factory(observer, controller):
        return OnlineScanOutcome(results=[], status=ScanStatus.CANCELLED)

    job = manager.start(cancel_factory, lambda o: "r", per_minute=4)
    await job.task
    assert job.status == JobStatus.CANCELLED

    async def boom_factory(observer, controller):
        raise RuntimeError("secret-key-leak-should-not-appear")

    job2 = manager.start(boom_factory, lambda o: "r", per_minute=4)
    await job2.task
    assert job2.status == JobStatus.ERROR
    assert "secret-key-leak" not in (job2.error or "")
    assert job2.error == "Internal error"


@pytest.mark.parametrize("raises", [False, True])
async def test_manager_retention_ttl_starts_at_terminal_completion(raises):
    clock = [0.0]
    release = asyncio.Event()
    manager = JobManager(ttl_seconds=10, monotonic=lambda: clock[0])

    async def factory(observer, controller):
        await release.wait()
        if raises:
            raise RuntimeError("boom")
        return OnlineScanOutcome(results=[], status=ScanStatus.COMPLETED)

    job = manager.start(factory, lambda outcome: "report", per_minute=4)
    clock[0] = 100.0
    assert manager.get(job.id) is job

    release.set()
    await job.task
    assert manager.get(job.id) is job

    clock[0] = 109.99
    assert manager.get(job.id) is job
    clock[0] = 110.0
    assert manager.get(job.id) is None


# ── ETA / warmup tests (JobSnapshot directly) ─────────────────────────────


def _apply_file_with_duration(
    snap: JobSnapshot,
    clock: list[float],
    index: int,
    *,
    duration_s: float = 5.0,
    stages: list[ScanStage] | None = None,
    report_category: str = "no_detections",
) -> None:
    """Apply FILE_STARTED, optional STAGE_CHANGED events, and FILE_FINISHED.

    Advances *clock* by *duration_s* between start and finish so the rolling-average
    model records a real per-file duration rather than zero.  *stages* defaults to
    ``[ScanStage.LOOKUP]``; pass an explicit list to test multi-request scenarios.
    """
    if stages is None:
        stages = [ScanStage.LOOKUP]
    snap.apply(ScanProgressEvent(type=EventType.FILE_STARTED, index=index, path=f"file_{index}"))
    for stage in stages:
        snap.apply(ScanProgressEvent(type=EventType.STAGE_CHANGED, stage=stage))
    clock[0] += duration_s
    snap.apply(
        ScanProgressEvent(
            type=EventType.FILE_FINISHED,
            index=index,
            report_category=report_category,
            risk_label=report_category,
            engine_state="found",
            had_error=False,
        )
    )


# ── Tests: action field on ScanProgressEvent ──────────────────────────────


def test_action_field_serializes_in_scan_progress_event():
    """ScanProgressEvent accepts an action field; as_dict includes it when set."""
    evt = ScanProgressEvent(type=EventType.FILE_FINISHED, action="uploaded")
    assert evt.as_dict()["action"] == "uploaded"


def test_action_field_omitted_when_none():
    """ScanProgressEvent.as_dict() drops action when it is None (consistent with other fields)."""
    evt = ScanProgressEvent(type=EventType.FILE_FINISHED)
    assert "action" not in evt.as_dict()


# ── Tests: uploaded counted from action, not engine_state ─────────────────────


def test_snapshot_uploaded_counted_from_action_upload_then_poll_failure():
    """Upload-then-poll-failure: action=uploaded + engine_state=error → still uploaded."""
    snap = JobSnapshot(per_minute=10)
    snap.apply(ScanProgressEvent(type=EventType.SCAN_STARTED, total=5))
    snap.apply(ScanProgressEvent(type=EventType.FILE_STARTED, index=0, path="a.bin"))
    snap.apply(
        ScanProgressEvent(
            type=EventType.FILE_FINISHED,
            index=0,
            report_category="high",
            risk_label="high",
            engine_state="error",
            action="uploaded",   # upload succeeded; only the poll failed
            had_error=True,
        )
    )
    assert snap.uploaded == 1


def test_snapshot_uploaded_counted_from_action_analysis_completed():
    """action=analysis_completed also counts as uploaded (full round-trip)."""
    snap = JobSnapshot(per_minute=10)
    snap.apply(ScanProgressEvent(type=EventType.SCAN_STARTED, total=5))
    snap.apply(ScanProgressEvent(type=EventType.FILE_STARTED, index=0, path="b.exe"))
    snap.apply(
        ScanProgressEvent(
            type=EventType.FILE_FINISHED,
            index=0,
            report_category="no_detections",
            risk_label="no_detections",
            engine_state="found",
            action="analysis_completed",
            had_error=False,
        )
    )
    assert snap.uploaded == 1


# ── Tests: category / attention / unknown overlap semantics ────────────────


def test_snapshot_unknown_excludes_skipped():
    """report_category=skipped does NOT increment unknown (or attention)."""
    snap = JobSnapshot(per_minute=10)
    snap.apply(ScanProgressEvent(type=EventType.SCAN_STARTED, total=5))
    snap.apply(ScanProgressEvent(type=EventType.FILE_STARTED, index=0, path="x"))
    snap.apply(
        ScanProgressEvent(
            type=EventType.FILE_FINISHED,
            index=0,
            report_category="skipped",
            risk_label="skipped",
            engine_state=None,
            had_error=False,
        )
    )
    assert snap.unknown == 0
    assert snap.attention == 0


def test_snapshot_unknown_but_suspicious_counts_in_both_attention_and_unknown():
    """unknown_but_suspicious increments BOTH attention and unknown (deliberate overlap)."""
    snap = JobSnapshot(per_minute=10)
    snap.apply(ScanProgressEvent(type=EventType.SCAN_STARTED, total=5))
    snap.apply(ScanProgressEvent(type=EventType.FILE_STARTED, index=0, path="x"))
    snap.apply(
        ScanProgressEvent(
            type=EventType.FILE_FINISHED,
            index=0,
            report_category="unknown_but_suspicious",
            risk_label="unknown",
            engine_state="not_found",
            had_error=False,
        )
    )
    assert snap.attention == 1
    assert snap.unknown == 1


def test_snapshot_full_inventory_counts_as_unknown_not_attention():
    """full_inventory increments unknown but NOT attention."""
    snap = JobSnapshot(per_minute=10)
    snap.apply(ScanProgressEvent(type=EventType.SCAN_STARTED, total=5))
    snap.apply(ScanProgressEvent(type=EventType.FILE_STARTED, index=0, path="x"))
    snap.apply(
        ScanProgressEvent(
            type=EventType.FILE_FINISHED,
            index=0,
            report_category="full_inventory",
            risk_label="skipped",
            engine_state=None,
            had_error=False,
        )
    )
    assert snap.unknown == 1
    assert snap.attention == 0


# ── ETA tests (clock advances between FILE_STARTED and FILE_FINISHED) ──────


def test_eta_none_during_warmup():
    """eta_seconds is None while fewer than _WARMUP (3) files have been processed."""
    clock = [0.0]
    snap = JobSnapshot(per_minute=10, monotonic=lambda: clock[0])
    snap.apply(ScanProgressEvent(type=EventType.SCAN_STARTED, total=10))
    for i in range(2):  # strictly below _WARMUP=3
        _apply_file_with_duration(snap, clock, i, duration_s=5.0)
    assert snap.eta_seconds is None


def test_eta_positive_after_warmup():
    """eta_seconds is a positive float once _WARMUP files complete and each took real time."""
    clock = [0.0]
    snap = JobSnapshot(per_minute=10, monotonic=lambda: clock[0])
    snap.apply(ScanProgressEvent(type=EventType.SCAN_STARTED, total=10))
    for i in range(3):  # exactly _WARMUP=3
        _apply_file_with_duration(snap, clock, i, duration_s=5.0)
    eta = snap.eta_seconds
    assert eta is not None
    assert eta > 0.0


def test_eta_rolling_average_drives_observed_term():
    """When per_minute is high (floor negligible), ETA ≈ rolling_avg * remaining.

    3 files × 5 s each → rolling_avg = 5.0, remaining = 7.
    expected_observed = 7 * 5.0 = 35.0.
    floor = 7 * (3/3) / 100 * 60 = 4.2 → negligible.
    """
    clock = [0.0]
    snap = JobSnapshot(per_minute=100, monotonic=lambda: clock[0])
    snap.apply(ScanProgressEvent(type=EventType.SCAN_STARTED, total=10))
    for i in range(3):
        _apply_file_with_duration(snap, clock, i, duration_s=5.0)
    expected_observed = 7 * 5.0  # remaining * rolling_avg
    eta = snap.eta_seconds
    assert eta is not None
    assert abs(eta - expected_observed) < 1.0


def test_eta_pacing_floor_dominates():
    """With per_minute=1 and tiny per-file durations, the pacing floor drives ETA.

    3 files × 0.001 s each → rolling_avg ≈ 0.
    floor = 7 * (live_requests/processed) / per_minute * 60
          = 7 * 1.0 / 1 * 60 = 420 s (one LOOKUP per file).
    """
    clock = [0.0]
    per_minute = 1
    total = 10
    snap = JobSnapshot(per_minute=per_minute, monotonic=lambda: clock[0])
    snap.apply(ScanProgressEvent(type=EventType.SCAN_STARTED, total=total))
    for i in range(3):
        _apply_file_with_duration(snap, clock, i, duration_s=0.001)
    remaining = total - 3  # 7
    # live_requests = 3 (one LOOKUP per file), processed = 3 → ratio = 1.0
    expected_floor = remaining * 1.0 / per_minute * 60  # 420.0
    eta = snap.eta_seconds
    assert eta is not None
    assert eta >= expected_floor


def test_eta_live_request_floor_reflects_actual_request_count():
    """Floor uses actual live-request count, NOT just file count.

    3 files, each going through LOOKUP + UPLOADING + POLLING = 3 requests/file = 9 total.
    floor = 7 * (9/3) / 1 * 60 = 1260 s — three times the single-stage floor (420 s).
    """
    clock = [0.0]
    per_minute = 1
    total = 10
    three_stages = [ScanStage.LOOKUP, ScanStage.UPLOADING, ScanStage.POLLING]
    snap = JobSnapshot(per_minute=per_minute, monotonic=lambda: clock[0])
    snap.apply(ScanProgressEvent(type=EventType.SCAN_STARTED, total=total))
    for i in range(3):
        _apply_file_with_duration(snap, clock, i, duration_s=0.001, stages=three_stages)
    remaining = total - 3  # 7
    # live_requests = 9, processed = 3 → ratio = 3.0
    expected_floor = remaining * 3.0 / per_minute * 60  # 1260.0
    eta = snap.eta_seconds
    assert eta is not None
    assert eta >= expected_floor


def test_eta_none_when_scan_complete():
    """eta_seconds is None when every file has been processed (processed >= total)."""
    clock = [0.0]
    total = 3
    snap = JobSnapshot(per_minute=10, monotonic=lambda: clock[0])
    snap.apply(ScanProgressEvent(type=EventType.SCAN_STARTED, total=total))
    for i in range(total):
        _apply_file_with_duration(snap, clock, i, duration_s=5.0)
    # processed (3) == total (3) → guard fires
    assert snap.eta_seconds is None
