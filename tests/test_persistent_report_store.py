import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from hscanner.report import build_scan_report
from hscanner.web.persistent_reports import PersistentReportStore


class Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def _report(report_id: str = "report-id"):
    return build_scan_report(
        Path("/scan"),
        [],
        online=True,
        upload_consent=False,
        report_id_factory=lambda: report_id,
        now=lambda: datetime(2026, 6, 28, 10, 0, tzinfo=UTC),
        engine_id="metadefender",
        engine_name="MetaDefender",
    )


def test_persistent_store_lists_unexpired_reports_newest_first(tmp_path) -> None:
    path = tmp_path / "reports.db"
    first = build_scan_report(
        Path("/first"),
        [],
        online=True,
        upload_consent=False,
        report_id_factory=lambda: "first",
        now=lambda: datetime(2026, 6, 28, 9, 0, tzinfo=UTC),
    )
    second = build_scan_report(
        Path("/second"),
        [],
        online=True,
        upload_consent=False,
        report_id_factory=lambda: "second",
        now=lambda: datetime(2026, 6, 28, 11, 0, tzinfo=UTC),
    )
    store = PersistentReportStore(path=path)
    store.put(first)
    store.put(second)

    listed = store.list_reports()

    assert [report.report_id for report in listed] == ["second", "first"]


def test_persistent_store_list_excludes_expired_reports(tmp_path) -> None:
    clock = Clock(datetime(2026, 6, 28, 10, 0, tzinfo=UTC))
    store = PersistentReportStore(
        path=tmp_path / "reports.db",
        retention_seconds=3600,
        now=clock,
    )
    store.put(_report())
    clock.value += timedelta(hours=2)

    assert store.list_reports() == []


def test_persistent_store_restores_report_after_new_instance(tmp_path) -> None:
    path = tmp_path / "reports.db"
    PersistentReportStore(path=path).put(_report())

    restored = PersistentReportStore(path=path).get("report-id")

    assert restored is not None
    assert restored.report_id == "report-id"
    assert restored.engine_id == "metadefender"
    assert restored.engine_name == "MetaDefender"


def test_persistent_store_expires_reports_by_last_access(tmp_path) -> None:
    clock = Clock(datetime(2026, 6, 28, 10, 0, tzinfo=UTC))
    path = tmp_path / "reports.db"
    store = PersistentReportStore(
        path=path,
        retention_seconds=7 * 24 * 3600,
        now=clock,
    )
    store.put(_report())
    clock.value += timedelta(days=6)
    assert store.get("report-id") is not None

    clock.value += timedelta(days=8)
    assert store.get("report-id") is None
    with sqlite3.connect(path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    assert count == 0


def test_persistent_store_dump_excludes_unrelated_secret(tmp_path) -> None:
    secret = "SECRET-KEY-DO-NOT-PERSIST"
    path = tmp_path / "reports.db"
    PersistentReportStore(path=path).put(_report())

    with sqlite3.connect(path) as conn:
        dump = "\n".join(conn.iterdump())

    assert "report-id" in dump
    assert secret not in dump
