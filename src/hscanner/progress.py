import asyncio
from dataclasses import dataclass, fields
from enum import StrEnum
from typing import Protocol


class ScanStage(StrEnum):
    HASHING = "hashing"
    LOOKUP = "lookup"
    UPLOADING = "uploading"
    POLLING = "polling"
    WAITING_RATE_LIMIT = "waiting_rate_limit"


class EventType(StrEnum):
    SCAN_STARTED = "scan_started"
    FILE_STARTED = "file_started"
    STAGE_CHANGED = "stage_changed"
    FILE_FINISHED = "file_finished"
    SCAN_FINISHED = "scan_finished"


@dataclass(frozen=True)
class ScanProgressEvent:
    type: EventType
    total: int | None = None
    index: int | None = None
    path: str | None = None
    stage: ScanStage | None = None
    report_category: str | None = None
    risk_label: str | None = None
    engine_state: str | None = None
    had_error: bool | None = None
    action: str | None = None
    status: str | None = None
    report_id: str | None = None
    online_pending: int | None = None
    bypassed: int | None = None
    engine_id: str | None = None
    outcome: str | None = None
    outcome_reason: str | None = None
    lookup_status: str | None = None
    upload_status: str | None = None

    def as_dict(self) -> dict[str, object]:
        out: dict[str, object] = {}
        for field in fields(self):
            value = getattr(self, field.name)
            if value is None:
                continue
            out[field.name] = value.value if isinstance(value, StrEnum) else value
        return out


class ScanObserver(Protocol):
    def __call__(self, event: ScanProgressEvent) -> None: ...


class ScanCancelled(Exception):
    """Cooperative cancel signal. A control signal, not a HScannerError."""


class ScanController:
    def __init__(self) -> None:
        self._cancelled = False
        self._resume = asyncio.Event()
        self._resume.set()  # not paused initially

    def pause(self) -> None:
        self._resume.clear()

    def resume(self) -> None:
        self._resume.set()

    def cancel(self) -> None:
        self._cancelled = True
        self._resume.set()  # release any paused checkpoint so it can observe the cancel

    @property
    def paused(self) -> bool:
        return not self._resume.is_set()

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    async def checkpoint(self) -> None:
        if self._cancelled:
            raise ScanCancelled()
        await self._resume.wait()
        if self._cancelled:
            raise ScanCancelled()


@dataclass
class ScanHooks:
    observer: ScanObserver | None = None
    controller: ScanController | None = None

    async def checkpoint(self) -> None:
        if self.controller is not None:
            await self.controller.checkpoint()

    def on_wait(self, seconds: float, stage: ScanStage) -> None:
        if self.observer is not None:
            self.observer(ScanProgressEvent(type=EventType.STAGE_CHANGED, stage=stage))
