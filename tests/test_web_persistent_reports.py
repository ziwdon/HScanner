from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from hscanner.report import build_scan_report
from hscanner.web.app import create_app
from hscanner.web.persistent_reports import PersistentReportStore
from hscanner.web.report_store import ReportRegistry


class Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def _report(report_id: str = "persisted-report"):
    return build_scan_report(
        Path("/scan"),
        [],
        online=True,
        upload_consent=False,
        report_id_factory=lambda: report_id,
        now=lambda: datetime(2026, 6, 28, 10, 0, tzinfo=UTC),
    )


def test_default_web_app_restores_persisted_report_after_restart(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    report = _report()
    first = create_app()
    first.state.report_registry.put(report)

    second = create_app()
    response = TestClient(second).get(f"/reports/{report.report_id}")

    assert response.status_code == 200
    assert "Triage report" in response.text


def test_history_page_lists_persisted_report_after_restart(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    report = _report()
    first = create_app()
    first.state.report_registry.put(report)

    second = create_app()
    response = TestClient(second).get("/history")

    assert response.status_code == 200
    assert "/scan" in response.text
    assert f'href="/reports/{report.report_id}"' in response.text


def test_web_report_page_returns_404_after_persistent_retention_expiry(tmp_path) -> None:
    clock = Clock(datetime(2026, 6, 28, 10, 0, tzinfo=UTC))
    store = PersistentReportStore(
        path=tmp_path / "reports.db",
        retention_seconds=3600,
        now=clock,
    )
    registry = ReportRegistry(persistent_store=store)
    report = _report()
    registry.put(report)
    clock.value += timedelta(hours=2)
    app = create_app(report_registry=ReportRegistry(persistent_store=store))

    response = TestClient(app).get(f"/reports/{report.report_id}")

    assert response.status_code == 404
    assert "Report expired or unavailable" in response.text
