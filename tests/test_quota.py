# tests/test_quota.py
from datetime import UTC, datetime

import pytest

from hscanner.budget import (
    QuotaCounter,
    QuotaExhausted,
    QuotaStopReason,
    RequestBudget,
    RequestKind,
)
from hscanner.store import open_global_store


class Clock:
    def __init__(self, dt):
        self.dt = dt

    def __call__(self):
        return self.dt


def test_remaining_ok_true_when_unset(tmp_path):
    qc = QuotaCounter(open_global_store(base_dir=tmp_path))
    assert qc.remaining_ok() is True
    qc.record()
    assert qc.remaining_ok() is True  # null budgets never cap


def test_daily_budget_caps_after_n_records(tmp_path):
    clock = Clock(datetime(2026, 6, 20, tzinfo=UTC))
    qc = QuotaCounter(open_global_store(base_dir=tmp_path), daily=2, now=clock)
    assert qc.remaining_ok()
    qc.record()
    qc.record()
    assert qc.remaining_ok() is False  # 2 used, daily=2


def test_all_exhausted_reasons_are_reported_in_deterministic_order(tmp_path):
    qc = QuotaCounter(open_global_store(base_dir=tmp_path), daily=1, monthly=1)
    qc.record()
    assert qc.exhausted_reasons() == (
        QuotaStopReason.DAILY,
        QuotaStopReason.MONTHLY,
    )


def test_counters_are_keyed_by_day_and_month(tmp_path):
    conn = open_global_store(base_dir=tmp_path)
    QuotaCounter(conn, now=Clock(datetime(2026, 6, 20, tzinfo=UTC))).record()
    keys = {r["period_key"]: r["count"] for r in conn.execute("SELECT * FROM quota_counter")}
    assert keys == {"virustotal:day:2026-06-20": 1, "virustotal:month:2026-06": 1}


def test_day_rollover_frees_the_daily_budget(tmp_path):
    conn = open_global_store(base_dir=tmp_path)
    day1 = QuotaCounter(conn, daily=1, now=Clock(datetime(2026, 6, 20, tzinfo=UTC)))
    day1.record()
    assert day1.remaining_ok() is False
    day2 = QuotaCounter(conn, daily=1, now=Clock(datetime(2026, 6, 21, tzinfo=UTC)))
    assert day2.remaining_ok() is True


def test_quota_counts_are_engine_scoped(tmp_path):
    from hscanner.budget import QuotaCounter
    from hscanner.store import open_global_store
    conn = open_global_store(tmp_path)
    vt = QuotaCounter(conn, engine_id="virustotal", daily=1)
    md = QuotaCounter(conn, engine_id="metadefender", daily=1)
    vt.record()
    assert vt.exhausted_reasons()       # vt hit its daily cap
    assert not md.exhausted_reasons()   # md is independent


async def test_request_budget_raises_quota_exhausted(tmp_path):
    qc = QuotaCounter(open_global_store(base_dir=tmp_path), daily=1)
    budget = RequestBudget(per_minute=100, quota=qc)
    await budget.acquire(RequestKind.LOOKUP)  # 1st ok, records
    with pytest.raises(QuotaExhausted) as exc_info:
        await budget.acquire(RequestKind.LOOKUP)  # 2nd over daily=1
    assert exc_info.value.reasons == (QuotaStopReason.DAILY,)
