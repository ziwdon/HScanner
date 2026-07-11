from datetime import UTC, datetime
from pathlib import Path

import pytest

from hscanner.report import build_scan_report
from hscanner.web.persistent_reports import PersistentReportStore
from hscanner.web.report_store import ReportRegistry


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def make_report():
    def factory(report_id: str):
        return build_scan_report(
            Path("/scan"),
            [],
            online=False,
            upload_consent=False,
            report_id_factory=lambda: report_id,
            now=lambda: datetime(2026, 6, 20, tzinfo=UTC),
        )

    return factory


@pytest.fixture
def report(make_report):
    return make_report("report-id")


def test_registry_returns_report_before_expiry(report) -> None:
    clock = FakeClock()
    store = ReportRegistry(max_reports=5, ttl_seconds=3600, monotonic=clock)
    store.put(report)
    assert store.get(report.report_id) is report


def test_registry_expires_from_creation_time(report) -> None:
    clock = FakeClock()
    store = ReportRegistry(max_reports=5, ttl_seconds=3600, monotonic=clock)
    store.put(report)
    clock.now = 3600
    assert store.get(report.report_id) is None


def test_registry_refreshes_report_ttl_on_access(report) -> None:
    clock = FakeClock()
    store = ReportRegistry(max_reports=5, ttl_seconds=3600, monotonic=clock)
    store.put(report)
    clock.now = 3000
    assert store.get(report.report_id) is report
    clock.now = 6500
    assert store.get(report.report_id) is report
    clock.now = 10100
    assert store.get(report.report_id) is None


def test_registry_evicts_oldest_at_capacity(make_report) -> None:
    clock = FakeClock()
    store = ReportRegistry(max_reports=2, ttl_seconds=3600, monotonic=clock)
    first = make_report("first")
    second = make_report("second")
    third = make_report("third")
    store.put(first)
    clock.now += 1
    store.put(second)
    clock.now += 1
    store.put(third)
    assert store.get("first") is None
    assert store.get("second") is second
    assert store.get("third") is third


def test_registry_loads_report_from_persistent_store_on_memory_miss(
    tmp_path, report
) -> None:
    db_path = tmp_path / "reports.db"
    first = ReportRegistry(persistent_store=PersistentReportStore(path=db_path))
    first.put(report)

    second = ReportRegistry(persistent_store=PersistentReportStore(path=db_path))
    restored = second.get(report.report_id)

    assert restored is not None
    assert restored.report_id == report.report_id
    assert restored.generated_at == report.generated_at


def test_registry_memory_access_refreshes_persistent_retention(tmp_path, report) -> None:
    class UtcClock:
        def __init__(self):
            self.now = datetime(2026, 6, 1, tzinfo=UTC)

        def __call__(self):
            return self.now

    clock = UtcClock()
    store = PersistentReportStore(
        path=tmp_path / "reports.db",
        retention_seconds=30 * 24 * 3600,
        now=clock,
    )
    registry = ReportRegistry(persistent_store=store)
    registry.put(report)

    clock.now = datetime(2026, 6, 30, tzinfo=UTC)
    assert registry.get(report.report_id) is report

    # A fresh registry must still find the row after the original 30-day
    # deadline because the in-memory access above renewed persistent retention.
    clock.now = datetime(2026, 7, 2, tzinfo=UTC)
    restored = ReportRegistry(persistent_store=store).get(report.report_id)
    assert restored is not None


class FailingPersistentStore:
    def put(self, report):
        raise OSError("persistent store is unavailable")

    def get(self, report_id):
        raise OSError("persistent store is unavailable")

    def list_reports(self):
        raise OSError("persistent store is unavailable")


def test_registry_put_keeps_in_memory_report_when_persistent_write_fails(report) -> None:
    registry = ReportRegistry(persistent_store=FailingPersistentStore())

    registry.put(report)

    assert registry.get(report.report_id) is report


def test_registry_memory_miss_ignores_persistent_read_failure() -> None:
    registry = ReportRegistry(persistent_store=FailingPersistentStore())

    assert registry.get("missing") is None


def test_registry_list_ignores_persistent_list_failure(report) -> None:
    registry = ReportRegistry(persistent_store=FailingPersistentStore())
    registry.put(report)

    assert registry.list_reports() == [report]
