import sqlite3

import pytest

from hscanner.budget import (
    BudgetExhausted,
    QuotaCounter,
    QuotaStopReason,
    RequestBudget,
    RequestKind,
    RequestMetrics,
)


class FakeClock:
    """Monotonic clock whose time only advances when sleep() is awaited."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def make_budget(
    per_minute: int = 4, max_requests: int | None = None
) -> tuple[RequestBudget, FakeClock]:
    clock = FakeClock()
    budget = RequestBudget(
        per_minute=per_minute,
        max_requests=max_requests,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
    )
    return budget, clock


async def test_acquire_counts_per_kind_and_total() -> None:
    budget, _ = make_budget()
    await budget.acquire(RequestKind.LOOKUP)
    await budget.acquire(RequestKind.LOOKUP)
    await budget.acquire(RequestKind.UPLOAD)
    assert budget.counts[RequestKind.LOOKUP] == 2
    assert budget.counts[RequestKind.UPLOAD] == 1
    assert budget.total == 3


async def test_does_not_sleep_below_per_minute() -> None:
    budget, clock = make_budget(per_minute=4)
    for _ in range(4):
        await budget.acquire(RequestKind.LOOKUP)
    assert clock.sleeps == []


async def test_sleeps_when_window_full() -> None:
    budget, clock = make_budget(per_minute=2)
    await budget.acquire(RequestKind.LOOKUP)  # t=0
    await budget.acquire(RequestKind.LOOKUP)  # t=0, window now full
    await budget.acquire(RequestKind.LOOKUP)  # must wait 60s for oldest to age out
    assert clock.sleeps == [60.0]
    assert clock.now == 60.0


async def test_ceiling_raises_before_counting() -> None:
    budget, _ = make_budget(max_requests=2)
    await budget.acquire(RequestKind.LOOKUP)
    await budget.acquire(RequestKind.LOOKUP)
    with pytest.raises(BudgetExhausted):
        await budget.acquire(RequestKind.LOOKUP)
    assert budget.total == 2  # the rejected acquire did not count


def test_zero_metrics_include_all_request_kinds_in_enum_order() -> None:
    metrics = RequestMetrics.zero()
    assert metrics.by_kind == tuple((kind.value, 0) for kind in RequestKind)
    assert metrics.total == 0


async def test_snapshot_reports_counts_and_pacing_wait() -> None:
    budget, _ = make_budget(per_minute=1)
    await budget.acquire(RequestKind.LOOKUP)
    await budget.acquire(RequestKind.UPLOAD)

    metrics = budget.snapshot()
    assert metrics.total == 2
    assert dict(metrics.by_kind) == {
        "lookup": 1,
        "upload": 1,
        "upload_url": 0,
        "poll": 0,
    }
    assert metrics.pacing_wait_count == 1
    assert metrics.pacing_wait_seconds == 60.0
    assert metrics.rate_limit_wait_count == 0
    assert metrics.rate_limit_wait_seconds == 0.0


def test_snapshot_accepts_rate_limit_wait_metrics() -> None:
    budget, _ = make_budget()
    metrics = budget.snapshot(rate_limit_wait_count=2, rate_limit_wait_seconds=3.5)
    assert metrics.rate_limit_wait_count == 2
    assert metrics.rate_limit_wait_seconds == 3.5


def _record_sleep(sleeps, clock):
    async def _sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock[0] += seconds
    return _sleep


async def test_acquire_calls_on_wait_before_pacing_sleep():
    sleeps: list[float] = []
    waits: list[float] = []
    clock = [0.0]

    budget = RequestBudget(
        per_minute=1,
        sleep=_record_sleep(sleeps, clock),
        monotonic=lambda: clock[0],
    )
    await budget.acquire(RequestKind.LOOKUP)  # first call: no wait
    await budget.acquire(RequestKind.LOOKUP, on_wait=waits.append)  # second: must pace
    assert sleeps  # a pacing sleep happened
    assert waits == [sleeps[0]]  # on_wait got the same duration


async def test_pacing_seconds_remaining_zero_with_room() -> None:
    budget, _ = make_budget(per_minute=4)
    await budget.acquire(RequestKind.LOOKUP)
    assert budget.pacing_seconds_remaining() == 0.0


async def test_pacing_seconds_remaining_positive_when_full() -> None:
    budget, _ = make_budget(per_minute=2)
    await budget.acquire(RequestKind.LOOKUP)  # t=0
    await budget.acquire(RequestKind.LOOKUP)  # t=0, window full
    # oldest is at t=0; 60s until it ages out
    assert budget.pacing_seconds_remaining() == 60.0


async def test_pacing_seconds_remaining_is_read_only() -> None:
    budget, _ = make_budget(per_minute=2)
    await budget.acquire(RequestKind.LOOKUP)
    await budget.acquire(RequestKind.LOOKUP)
    budget.pacing_seconds_remaining()
    budget.pacing_seconds_remaining()
    assert budget.total == 2  # peeking did not consume window slots
    assert len(budget._window) == 2


class FailingQuotaConnection:
    def execute(self, *args, **kwargs):
        raise sqlite3.OperationalError("attempt to write a readonly database")

    def commit(self):
        raise AssertionError("commit should not run after failed execute")


async def test_quota_record_failure_does_not_abort_request_acquire() -> None:
    counter = QuotaCounter(FailingQuotaConnection())
    budget = RequestBudget(quota=counter)

    await budget.acquire(RequestKind.LOOKUP)

    assert budget.counts[RequestKind.LOOKUP] == 1


async def test_quota_record_failure_keeps_session_counts_for_limits() -> None:
    counter = QuotaCounter(FailingQuotaConnection(), daily=1, monthly=10)
    budget = RequestBudget(quota=counter)

    await budget.acquire(RequestKind.LOOKUP)

    assert counter.exhausted_reasons() == (QuotaStopReason.DAILY,)
