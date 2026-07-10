# src/hscanner/web/jobs.py
import asyncio
import secrets
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from enum import StrEnum
from statistics import mean

from hscanner.models import ScanStatus
from hscanner.progress import EventType, ScanController, ScanProgressEvent

_WARMUP = 3
_RECENT_WINDOW = 10


class JobStatus(StrEnum):
    RUNNING = "running"
    PAUSED = "paused"
    FINISHED = "finished"
    CANCELLED = "cancelled"
    ERROR = "error"


class JobBusy(Exception):
    """A scan job is already active."""


class JobSnapshot:
    def __init__(self, *, per_minute: int, monotonic: Callable[[], float] = time.monotonic) -> None:
        self.per_minute = max(1, per_minute)
        self._monotonic = monotonic
        self.total = 0
        self.processed = 0
        self.no_detections = 0
        self.attention = 0
        self.scanned = 0
        self.infected = 0
        self.needs_attention = 0
        self.uploaded = 0
        self.skipped = 0
        self.unknown = 0
        self.errors = 0
        self.online_pending = 0
        self.bypassed = 0
        self.current_path: str | None = None
        self.current_stage: str | None = None
        self.current_engine_id: str | None = None
        self._started_at: float | None = None
        self._file_start: float | None = None
        self._recent_durations: deque[float] = deque(maxlen=_RECENT_WINDOW)
        self._live_requests = 0

    _ATTENTION = {"high", "medium", "low", "unknown_but_suspicious", "upload_blocked"}
    _LIVE_STAGES = {"lookup", "uploading", "polling"}

    def apply(self, event: ScanProgressEvent) -> None:
        if event.type == EventType.SCAN_STARTED:
            self.total = event.total or 0
            self.online_pending = event.online_pending or 0
            self.bypassed = event.bypassed or 0
            self._started_at = self._monotonic()
        elif event.type == EventType.FILE_STARTED:
            self.current_path = event.path
            self.current_stage = None
            self._file_start = self._monotonic()
        elif event.type == EventType.STAGE_CHANGED:
            self.current_stage = str(event.stage) if event.stage is not None else None
            if event.engine_id is not None:
                self.current_engine_id = event.engine_id
            if event.stage in self._LIVE_STAGES:
                self._live_requests += 1
        elif event.type == EventType.FILE_FINISHED:
            if self._file_start is not None:
                self._recent_durations.append(self._monotonic() - self._file_start)
                self._file_start = None
            self.processed += 1
            if event.outcome is not None:
                if event.lookup_status != "not_checked":
                    self.scanned += 1
                if event.upload_status in (
                    "uploaded", "analysis_complete", "analysis_failed"
                ):
                    self.uploaded += 1
                if event.outcome == "infected":
                    self.infected += 1
                elif event.outcome == "needs_attention":
                    self.needs_attention += 1
                elif event.outcome == "skipped":
                    self.skipped += 1
                elif event.outcome == "error":
                    self.errors += 1
            else:
                if event.action in ("uploaded", "analysis_completed"):
                    self.uploaded += 1
                if event.had_error:
                    self.errors += 1
            category = event.report_category
            if category == "no_detections":
                self.no_detections += 1
            if category in self._ATTENTION:
                self.attention += 1
            if category in ("unknown_but_suspicious", "full_inventory"):
                self.unknown += 1

    @property
    def eta_seconds(self) -> float | None:
        if self.processed < _WARMUP or self._started_at is None or self.processed >= self.total:
            return None
        remaining = self.total - self.processed
        rolling_seconds_per_file = mean(self._recent_durations) if self._recent_durations else 0.0
        observed = remaining * rolling_seconds_per_file
        live_requests_per_file = self._live_requests / self.processed
        floor = remaining * live_requests_per_file / self.per_minute * 60
        return max(observed, floor)

    def to_dict(self) -> dict[str, object]:
        return {
            "total": self.total,
            "processed": self.processed,
            "scanned": self.scanned,
            "infected": self.infected,
            "needs_attention": self.needs_attention,
            "uploaded": self.uploaded,
            "skipped": self.skipped,
            "errors": self.errors,
            "online_pending": self.online_pending,
            "bypassed": self.bypassed,
            "current_path": self.current_path,
            "current_stage": self.current_stage,
            "current_engine_id": self.current_engine_id,
            "eta_seconds": self.eta_seconds,
        }


class ScanJob:
    def __init__(self, job_id: str, *, per_minute: int, queue_maxsize: int = 256) -> None:
        self.id = job_id
        self.status = JobStatus.RUNNING
        self.controller = ScanController()
        self.snapshot = JobSnapshot(per_minute=per_minute)
        self.scan_status: ScanStatus | None = None
        self.report_id: str | None = None
        self.error: str | None = None
        self.task: asyncio.Task | None = None
        self._queue_maxsize = queue_maxsize
        self._subscribers: set[asyncio.Queue] = set()

    def __call__(self, event: ScanProgressEvent) -> None:
        self.snapshot.apply(event)
        for queue in self._subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass  # snapshot is authoritative; dropping intermediate events is safe

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=self._queue_maxsize)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    def pause(self) -> None:
        self.controller.pause()
        if self.status == JobStatus.RUNNING:
            self.status = JobStatus.PAUSED

    def resume(self) -> None:
        self.controller.resume()
        if self.status == JobStatus.PAUSED:
            self.status = JobStatus.RUNNING

    def cancel(self) -> None:
        self.controller.cancel()

    @property
    def is_terminal(self) -> bool:
        return self.status in (JobStatus.FINISHED, JobStatus.CANCELLED, JobStatus.ERROR)


class JobManager:
    def __init__(
        self,
        *,
        max_jobs: int = 5,
        ttl_seconds: float = 3600,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_jobs = max_jobs
        self.ttl_seconds = ttl_seconds
        self._monotonic = monotonic
        self._jobs: OrderedDict[str, tuple[float, ScanJob]] = OrderedDict()

    def _active(self) -> ScanJob | None:
        for _, job in self._jobs.values():
            if not job.is_terminal:
                return job
        return None

    def start(self, scan_coro_factory, finalize, *, per_minute: int) -> ScanJob:
        self._prune()
        if self._active() is not None:
            raise JobBusy("a scan is already in progress")
        job = ScanJob(secrets.token_urlsafe(18), per_minute=per_minute)
        self._jobs[job.id] = (self._monotonic(), job)
        while len(self._jobs) > self.max_jobs:
            self._jobs.popitem(last=False)
        job.task = asyncio.create_task(self._run(job, scan_coro_factory, finalize))
        return job

    async def _run(self, job: ScanJob, scan_coro_factory, finalize) -> None:
        try:
            outcome = await scan_coro_factory(job, job.controller)
            job.scan_status = outcome.status
            if outcome.status == ScanStatus.CANCELLED:
                job.status = JobStatus.CANCELLED
            else:
                job.status = JobStatus.FINISHED
            job.report_id = finalize(outcome)
        except Exception:
            job.status = JobStatus.ERROR
            job.error = "Internal error"  # credential-safe: never a traceback or the key
        finally:
            if job.id in self._jobs:
                self._jobs[job.id] = (self._monotonic(), job)

    def get(self, job_id: str) -> ScanJob | None:
        self._prune()
        item = self._jobs.get(job_id)
        return item[1] if item is not None else None

    def _prune(self) -> None:
        now = self._monotonic()
        expired = [
            jid for jid, (retention_start, job) in self._jobs.items()
            if job.is_terminal and now - retention_start >= self.ttl_seconds
        ]
        for jid in expired:
            del self._jobs[jid]


class FileScanJob:
    def __init__(self, job_id: str, report_id: str, index: int, queue_maxsize: int = 64) -> None:
        self.id = job_id
        self.report_id = report_id
        self.index = index
        self.state = "queued"
        self.result = None
        self.error: str | None = None
        self.task: asyncio.Task | None = None
        self._queue_maxsize = queue_maxsize
        self._subscribers: set[asyncio.Queue] = set()

    def _emit(self, state: str) -> None:
        self.state = state
        for queue in self._subscribers:
            try:
                queue.put_nowait(state)
            except asyncio.QueueFull:
                pass

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=self._queue_maxsize)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    @property
    def is_terminal(self) -> bool:
        return self.state in ("done", "error")


class FileScanManager:
    def __init__(
        self,
        *,
        job_scan_guard: Callable[[], bool],
        max_jobs: int = 32,
        ttl_seconds: float = 3600,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._guard = job_scan_guard
        self.max_jobs = max_jobs
        self.ttl_seconds = ttl_seconds
        self._monotonic = monotonic
        self._jobs: OrderedDict[str, tuple[float, FileScanJob]] = OrderedDict()
        self._lock = asyncio.Lock()

    def find(self, report_id: str, index: int) -> FileScanJob | None:
        for _, job in self._jobs.values():
            if job.report_id == report_id and job.index == index and not job.is_terminal:
                return job
        return None

    def latest(self, report_id: str, index: int) -> "FileScanJob | None":
        match = None
        for _, job in self._jobs.values():
            if job.report_id == report_id and job.index == index:
                match = job  # iteration is insertion order; keep the most recent
        return match

    def get(self, job_id: str) -> FileScanJob | None:
        item = self._jobs.get(job_id)
        return item[1] if item is not None else None

    def has_active(self) -> bool:
        return any(not job.is_terminal for _, job in self._jobs.values())

    def enqueue(self, report_id: str, index: int, coro_factory) -> FileScanJob:
        if self._guard():
            raise JobBusy("a scan is already in progress")
        existing = self.find(report_id, index)
        if existing is not None:
            return existing
        job = FileScanJob(secrets.token_urlsafe(12), report_id, index)
        self._jobs[job.id] = (self._monotonic(), job)
        while len(self._jobs) > self.max_jobs:
            self._jobs.popitem(last=False)
        job.task = asyncio.create_task(self._run(job, coro_factory))
        return job

    async def _run(self, job: FileScanJob, coro_factory) -> None:
        async with self._lock:  # serialize: one VT consumer at a time
            try:
                job._emit("uploading")
                result = await coro_factory()
                job.result = result
                job._emit("done")
            except Exception:
                job.error = "Internal error"  # credential-safe
                job._emit("error")
            finally:
                self._jobs[job.id] = (self._monotonic(), job)


class BatchFileScanJob:
    HISTORY_LIMIT = 200

    def __init__(
        self,
        job_id: str,
        report_id: str,
        indices: list[int],
        queue_maxsize: int = 256,
    ) -> None:
        self.id = job_id
        self.report_id = report_id
        self.indices = list(indices)
        self.state = "queued"
        self.error: str | None = None
        self.task: asyncio.Task | None = None
        self.cancel_requested = False
        self._queue_maxsize = queue_maxsize
        self._subscribers: set[asyncio.Queue] = set()
        self.last_event: dict[str, object] = {
            "state": self.state,
            "job_id": self.id,
            "report_id": self.report_id,
            "total": len(self.indices),
            "processed": 0,
        }
        self.history: list[dict[str, object]] = [dict(self.last_event)]

    def emit(self, data: dict[str, object]) -> None:
        event = {
            "job_id": self.id,
            "report_id": self.report_id,
            **data,
        }
        state = event.get("state")
        if isinstance(state, str):
            self.state = state
        self.last_event = event
        self.history.append(event)
        if len(self.history) > self.HISTORY_LIMIT:
            self.history = self.history[-self.HISTORY_LIMIT:]
        for queue in self._subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=self._queue_maxsize)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    def replay_events(self) -> list[dict[str, object]]:
        return [
            {
                "state": "snapshot",
                "job_id": self.id,
                "report_id": self.report_id,
                "last": self.last_event,
            },
            *self.history,
        ]

    def cancel(self) -> None:
        self.cancel_requested = True

    @property
    def is_terminal(self) -> bool:
        return self.state in ("done", "cancelled", "error")


class BatchFileScanManager:
    def __init__(
        self,
        *,
        job_scan_guard: Callable[[], bool],
        max_jobs: int = 16,
        ttl_seconds: float = 3600,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._guard = job_scan_guard
        self.max_jobs = max_jobs
        self.ttl_seconds = ttl_seconds
        self._monotonic = monotonic
        self._jobs: OrderedDict[str, tuple[float, BatchFileScanJob]] = OrderedDict()

    def active_for_report(self, report_id: str) -> BatchFileScanJob | None:
        self._prune()
        for _, job in self._jobs.values():
            if job.report_id == report_id and not job.is_terminal:
                return job
        return None

    def recent_for_report(self, report_id: str) -> BatchFileScanJob | None:
        self._prune()
        for _, job in reversed(self._jobs.values()):
            if job.report_id == report_id:
                return job
        return None

    def get(self, job_id: str) -> BatchFileScanJob | None:
        self._prune()
        item = self._jobs.get(job_id)
        return item[1] if item is not None else None

    def has_active(self) -> bool:
        self._prune()
        return any(not job.is_terminal for _, job in self._jobs.values())

    def enqueue(self, report_id: str, indices: list[int], runner) -> BatchFileScanJob:
        if self._guard():
            raise JobBusy("a folder scan is already in progress")
        existing = self.active_for_report(report_id)
        if existing is not None:
            return existing
        if self.has_active():
            raise JobBusy("a batch file scan is already in progress")
        job = BatchFileScanJob(secrets.token_urlsafe(12), report_id, indices)
        self._jobs[job.id] = (self._monotonic(), job)
        while len(self._jobs) > self.max_jobs:
            terminal_id = next(
                (jid for jid, (_, old_job) in self._jobs.items() if old_job.is_terminal),
                None,
            )
            if terminal_id is None:
                break
            del self._jobs[terminal_id]
        job.task = asyncio.create_task(self._run(job, runner))
        return job

    async def _run(self, job: BatchFileScanJob, runner) -> None:
        try:
            job.emit({"state": "running", "total": len(job.indices), "processed": 0})
            await runner(job)
            if not job.is_terminal:
                job.emit({"state": "done"})
        except Exception:
            job.error = "Internal error"
            job.emit({"state": "error", "error": job.error})
        finally:
            self._jobs[job.id] = (self._monotonic(), job)

    def _prune(self) -> None:
        now = self._monotonic()
        expired = [
            jid for jid, (retention_start, job) in self._jobs.items()
            if job.is_terminal and now - retention_start >= self.ttl_seconds
        ]
        for jid in expired:
            del self._jobs[jid]
