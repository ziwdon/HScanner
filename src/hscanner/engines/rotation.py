from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from hscanner.budget import QuotaStopReason, RequestMetrics


def seconds_until_utc_reset(reason: str, now: datetime) -> float:
    """Seconds from ``now`` until the next UTC day or month boundary."""
    if reason == "monthly":
        if now.month == 12:
            nxt = now.replace(
                year=now.year + 1, month=1, day=1, hour=0, minute=0, second=0, microsecond=0
            )
        else:
            nxt = now.replace(
                month=now.month + 1, day=1, hour=0, minute=0, second=0, microsecond=0
            )
    else:  # daily (default)
        nxt = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return max(0.0, (nxt - now).total_seconds())


@dataclass
class EngineSlot:
    engine: Any  # ScanEngine
    cooldown_until: float = 0.0      # monotonic deadline; 0 = available
    cool_reason: str | None = None


class EngineRotation:
    def __init__(
        self,
        slots: list[EngineSlot],
        *,
        wait_threshold: float = 300.0,
        monotonic: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._slots = slots
        self.wait_threshold = wait_threshold
        self._monotonic = monotonic
        self._now = now

    def _available(self, slot: EngineSlot, now: float) -> bool:
        return slot.cooldown_until <= now

    def next_available(self) -> EngineSlot | None:
        now = self._monotonic()
        for slot in self._slots:
            if not self._available(slot, now):
                continue
            budget = getattr(slot.engine, "budget", None)
            quota = getattr(budget, "quota", None) if budget is not None else None
            if quota is not None:
                reasons = quota.exhausted_reasons()
                if reasons:
                    self.cool_quota(slot, reasons)
                    continue
            pacing = budget.pacing_seconds_remaining() if budget is not None else 0.0
            if pacing > 0:
                self.cool(slot, seconds=pacing, reason="pacing")
                continue
            return slot
        return None

    def cool(self, slot: EngineSlot, *, seconds: float, reason: str) -> None:
        slot.cooldown_until = self._monotonic() + seconds
        slot.cool_reason = reason

    def cool_quota(self, slot: EngineSlot, reasons: tuple[QuotaStopReason, ...]) -> None:
        reason = "monthly" if QuotaStopReason.MONTHLY in reasons else "daily"
        seconds = seconds_until_utc_reset(reason, self._now())
        self.cool(slot, seconds=seconds, reason=reason)

    def seconds_until_next(self) -> float | None:
        now = self._monotonic()
        remaining = [
            slot.cooldown_until - now
            for slot in self._slots
            if 0 < slot.cooldown_until - now != float("inf")
        ]
        if not remaining:
            return None
        return max(0.0, min(remaining))

    def all_long_cooled(self) -> bool:
        now = self._monotonic()
        return all(
            slot.cooldown_until - now > self.wait_threshold for slot in self._slots
        )

    def all_cooled_for(self, reason: str) -> bool:
        now = self._monotonic()
        return all(
            slot.cooldown_until > now and slot.cool_reason == reason
            for slot in self._slots
        )

    def cooled_reasons(self) -> set[str]:
        """Return reasons for slots that are currently cooling."""
        now = self._monotonic()
        return {
            slot.cool_reason
            for slot in self._slots
            if slot.cooldown_until > now and slot.cool_reason is not None
        }

    def snapshots(self) -> dict[str, RequestMetrics]:
        return {slot.engine.info.id: slot.engine.metrics_snapshot() for slot in self._slots}
