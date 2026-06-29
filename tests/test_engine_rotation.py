from dataclasses import dataclass
from datetime import UTC, datetime

import pytest

from hscanner.budget import QuotaStopReason
from hscanner.engines.rotation import (
    EngineRotation,
    EngineSlot,
    seconds_until_utc_reset,
)


@dataclass
class _Info:
    id: str
    display_name: str = "x"
    default_per_minute: int = 4


class FakeBudget:
    def __init__(self, pacing: float = 0.0, reasons=()) -> None:
        self._pacing = pacing
        self._reasons = tuple(reasons)

    def pacing_seconds_remaining(self, now=None) -> float:
        return self._pacing

    @property
    def quota(self):
        outer = self

        class _Q:
            def exhausted_reasons(self_inner):
                return outer._reasons

        return _Q() if outer._reasons else None


class FakeEngine:
    def __init__(self, engine_id: str, *, pacing=0.0, reasons=()) -> None:
        self.info = _Info(engine_id)
        self.budget = FakeBudget(pacing=pacing, reasons=reasons)

    def metrics_snapshot(self):
        return "metrics-" + self.info.id


def make_rotation(*engines, wait_threshold=300.0):
    clock = {"now": 1000.0}
    rotation = EngineRotation(
        [EngineSlot(e) for e in engines],
        wait_threshold=wait_threshold,
        monotonic=lambda: clock["now"],
    )
    return rotation, clock


def test_next_available_returns_first_in_priority_order():
    rotation, _ = make_rotation(FakeEngine("virustotal"), FakeEngine("metadefender"))
    slot = rotation.next_available()
    assert slot.engine.info.id == "virustotal"


def test_cooled_slot_is_skipped_then_reavailable():
    rotation, clock = make_rotation(FakeEngine("virustotal"), FakeEngine("metadefender"))
    first = rotation.next_available()
    rotation.cool(first, seconds=30, reason="rate_limited")
    assert rotation.next_available().engine.info.id == "metadefender"
    clock["now"] += 31
    assert rotation.next_available().engine.info.id == "virustotal"


def test_full_window_engine_is_cooled_pacing_and_skipped():
    rotation, _ = make_rotation(
        FakeEngine("virustotal", pacing=12.0), FakeEngine("metadefender")
    )
    slot = rotation.next_available()
    assert slot.engine.info.id == "metadefender"
    assert rotation.seconds_until_next() == pytest.approx(12.0)


def test_quota_exhausted_engine_is_cooled_long_and_skipped():
    rotation, _ = make_rotation(
        FakeEngine("virustotal", reasons=(QuotaStopReason.DAILY,)),
        FakeEngine("metadefender"),
    )
    slot = rotation.next_available()
    assert slot.engine.info.id == "metadefender"


def test_all_cooled_returns_none_and_seconds_until_next():
    rotation, _ = make_rotation(FakeEngine("virustotal"), FakeEngine("metadefender"))
    for slot in list(rotation._slots):
        rotation.cool(slot, seconds=45, reason="rate_limited")
    assert rotation.next_available() is None
    assert rotation.seconds_until_next() == pytest.approx(45.0)


def test_all_long_cooled_and_all_cooled_for():
    rotation, _ = make_rotation(FakeEngine("virustotal"), FakeEngine("metadefender"))
    for slot in list(rotation._slots):
        rotation.cool(slot, seconds=float("inf"), reason="auth")
    assert rotation.all_long_cooled() is True
    assert rotation.all_cooled_for("auth") is True
    assert rotation.all_cooled_for("budget") is False
    assert rotation.seconds_until_next() is None


def test_snapshots_keyed_by_engine_id():
    rotation, _ = make_rotation(FakeEngine("virustotal"), FakeEngine("metadefender"))
    assert rotation.snapshots() == {
        "virustotal": "metrics-virustotal",
        "metadefender": "metrics-metadefender",
    }


def test_seconds_until_utc_reset_daily_is_within_a_day():
    now = datetime(2026, 6, 23, 10, 0, 0, tzinfo=UTC)
    secs = seconds_until_utc_reset("daily", now)
    assert 0 < secs <= 24 * 3600


def test_seconds_until_utc_reset_monthly_is_positive():
    now = datetime(2026, 6, 23, 10, 0, 0, tzinfo=UTC)
    assert seconds_until_utc_reset("monthly", now) > 0


def test_seconds_until_utc_reset_monthly_december_rolls_to_january():
    now = datetime(2026, 12, 15, 10, 0, 0, tzinfo=UTC)
    secs = seconds_until_utc_reset("monthly", now)
    # Dec 15 10:00 -> Jan 1 00:00 = 16 days 14 hours
    assert secs == pytest.approx((16 * 24 + 14) * 3600.0)


def test_cool_quota_monthly_sets_long_cooldown():
    rotation, _ = make_rotation(FakeEngine("virustotal"), FakeEngine("metadefender"))
    slot = rotation._slots[0]
    rotation.cool_quota(slot, (QuotaStopReason.MONTHLY,))
    assert slot.cool_reason == "monthly"
    assert slot.cooldown_until > rotation._monotonic()


def test_quota_exhausted_engine_slot_is_mutated_by_next_available():
    rotation, _ = make_rotation(
        FakeEngine("virustotal", reasons=(QuotaStopReason.DAILY,)),
        FakeEngine("metadefender"),
    )
    rotation.next_available()
    vt_slot = rotation._slots[0]
    assert vt_slot.cool_reason == "daily"
    assert vt_slot.cooldown_until > rotation._monotonic()
