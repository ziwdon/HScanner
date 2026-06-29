import asyncio
import sqlite3
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum


class RequestKind(StrEnum):
    LOOKUP = "lookup"
    UPLOAD = "upload"
    UPLOAD_URL = "upload_url"
    POLL = "poll"


class QuotaStopReason(StrEnum):
    PER_SCAN = "per_scan"
    DAILY = "daily"
    MONTHLY = "monthly"


@dataclass(frozen=True)
class RequestMetrics:
    by_kind: tuple[tuple[str, int], ...]
    pacing_wait_count: int = 0
    pacing_wait_seconds: float = 0.0
    rate_limit_wait_count: int = 0
    rate_limit_wait_seconds: float = 0.0

    @property
    def total(self) -> int:
        return sum(count for _, count in self.by_kind)

    @classmethod
    def zero(cls) -> "RequestMetrics":
        return cls(by_kind=tuple((kind.value, 0) for kind in RequestKind))


class BudgetExhausted(Exception):
    """Per-scan request ceiling reached. A control signal, not a HScannerError."""


class QuotaExhausted(Exception):
    """Daily/monthly engine quota reached. A control signal, not a HScannerError."""

    def __init__(self, reasons: tuple[QuotaStopReason, ...]) -> None:
        self.reasons = reasons
        super().__init__(f"engine quota exhausted: {', '.join(map(str, reasons))}")


class QuotaCounter:
    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        engine_id: str = "virustotal",
        daily: int | None = None,
        monthly: int | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.conn = conn
        self.engine_id = engine_id
        self.daily = daily
        self.monthly = monthly
        self._now = now

    def _keys(self) -> tuple[str, str]:
        now = self._now()
        return (
            f"{self.engine_id}:day:{now:%Y-%m-%d}",
            f"{self.engine_id}:month:{now:%Y-%m}",
        )

    def _count(self, key: str) -> int:
        row = self.conn.execute(
            "SELECT count FROM quota_counter WHERE period_key=?", (key,)
        ).fetchone()
        return row["count"] if row else 0

    def remaining_ok(self) -> bool:
        return not self.exhausted_reasons()

    def exhausted_reasons(self) -> tuple[QuotaStopReason, ...]:
        day_key, month_key = self._keys()
        reasons: list[QuotaStopReason] = []
        if self.daily is not None and self._count(day_key) >= self.daily:
            reasons.append(QuotaStopReason.DAILY)
        if self.monthly is not None and self._count(month_key) >= self.monthly:
            reasons.append(QuotaStopReason.MONTHLY)
        return tuple(reasons)

    def record(self) -> None:
        for key in self._keys():
            self.conn.execute(
                "INSERT INTO quota_counter (period_key, count) VALUES (?, 1) "
                "ON CONFLICT(period_key) DO UPDATE SET count = count + 1",
                (key,),
            )
        self.conn.commit()


class RequestBudget:
    def __init__(
        self,
        per_minute: int = 4,
        max_requests: int | None = None,
        *,
        quota: "QuotaCounter | None" = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.per_minute = per_minute
        self.max_requests = max_requests
        self.quota = quota
        self._sleep = sleep
        self._monotonic = monotonic
        self._window: deque[float] = deque()
        self.counts: dict[RequestKind, int] = {kind: 0 for kind in RequestKind}
        self.pacing_wait_count = 0
        self.pacing_wait_seconds = 0.0

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    async def acquire(
        self,
        kind: RequestKind,
        *,
        on_wait: "Callable[[float], None] | None" = None,
    ) -> None:
        if self.max_requests is not None and self.total >= self.max_requests:
            raise BudgetExhausted(f"per-scan request ceiling {self.max_requests} reached")
        if self.quota is not None:
            reasons = self.quota.exhausted_reasons()
            if reasons:
                raise QuotaExhausted(reasons)
        self._evict_old(self._monotonic())
        if len(self._window) >= self.per_minute:
            wait = 60 - (self._monotonic() - self._window[0])
            if wait > 0:
                if on_wait is not None:
                    on_wait(wait)
                await self._sleep(wait)
                self.pacing_wait_count += 1
                self.pacing_wait_seconds += wait
            self._evict_old(self._monotonic())
        self._window.append(self._monotonic())
        self.counts[kind] += 1
        if self.quota is not None:
            self.quota.record()

    def snapshot(
        self,
        *,
        rate_limit_wait_count: int = 0,
        rate_limit_wait_seconds: float = 0.0,
    ) -> RequestMetrics:
        return RequestMetrics(
            by_kind=tuple((kind.value, self.counts[kind]) for kind in RequestKind),
            pacing_wait_count=self.pacing_wait_count,
            pacing_wait_seconds=self.pacing_wait_seconds,
            rate_limit_wait_count=rate_limit_wait_count,
            rate_limit_wait_seconds=rate_limit_wait_seconds,
        )

    def pacing_seconds_remaining(self, now: float | None = None) -> float:
        """Seconds until a request could proceed under the per-minute window.

        Read-only: does not evict or append. Returns 0.0 if there is room now.
        """
        current = self._monotonic() if now is None else now
        live = [t for t in self._window if current - t < 60]
        if len(live) < self.per_minute:
            return 0.0
        wait = 60 - (current - live[0])
        return wait if wait > 0 else 0.0

    def _evict_old(self, now: float) -> None:
        while self._window and now - self._window[0] >= 60:
            self._window.popleft()
