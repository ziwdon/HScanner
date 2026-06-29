import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from hscanner.engines.base import EngineInfo
from hscanner.report import build_scan_report
from hscanner.web.app import create_app
from hscanner.web.report_store import ReportRegistry


def test_homepage_loads() -> None:
    client = TestClient(create_app())

    response = client.get("/")

    assert response.status_code == 200
    assert "HScanner" in response.text


def test_settings_page_mentions_api_key() -> None:
    client = TestClient(create_app())

    response = client.get("/settings")

    assert response.status_code == 200
    assert "VirusTotal API key" in response.text


def test_top_nav_places_history_between_scan_and_settings() -> None:
    response = TestClient(create_app()).get("/")

    assert response.status_code == 200
    assert response.text.index('href="/">Scan</a>') < response.text.index(
        'href="/history">History</a>'
    )
    assert response.text.index('href="/history">History</a>') < response.text.index(
        'href="/settings">Settings</a>'
    )


def test_history_page_empty_state() -> None:
    app = create_app(report_registry=ReportRegistry())

    response = TestClient(app).get("/history")

    assert response.status_code == 200
    assert "Scan history" in response.text
    assert "No stored reports" in response.text
    assert 'class="navlink active" href="/history"' in response.text


def test_history_page_lists_stored_reports() -> None:
    registry = ReportRegistry()
    report = build_scan_report(
        Path("/tmp/hscanner-target"),
        [],
        online=True,
        upload_consent=False,
        report_id_factory=lambda: "history-report",
        engine_id="combined",
        engine_name="Combined",
    )
    registry.put(report)
    app = create_app(report_registry=registry)

    response = TestClient(app).get("/history")

    assert response.status_code == 200
    assert "/tmp/hscanner-target" in response.text
    assert "Combined" in response.text
    assert 'href="/reports/history-report"' in response.text
    assert "0 infected" in response.text
    assert "0 needs attention" in response.text


class FakeKeyring:
    def __init__(self, value: str | None = None) -> None:
        self.value: str | None = value

    def get_password(self, service: str, username: str) -> str | None:
        return self.value

    def set_password(self, service: str, username: str, password: str) -> None:
        self.value = password

    def delete_password(self, service: str, username: str) -> None:
        self.value = None


def test_settings_can_save_and_clear_key() -> None:
    fake = FakeKeyring()
    client = TestClient(create_app(keyring_module=fake), follow_redirects=False)

    save_response = client.post(
        "/settings/api-key", data={"api_key": "abc", "engine": "virustotal"}
    )
    assert save_response.status_code == 303
    assert fake.value == "abc"

    clear_response = client.post("/settings/api-key/clear", data={"engine": "virustotal"})
    assert clear_response.status_code == 303
    assert fake.value is None


def test_scan_nonexistent_folder_returns_400() -> None:
    # Fix #6: posting a non-existent folder must return 400, not 500.
    fake = FakeKeyring()  # no key stored → local-only scan path
    client = TestClient(create_app(keyring_module=fake))

    response = client.post(
        "/scan",
        data={"folder": "/nonexistent/path/xyz", "upload_eligible": "false"},
    )

    assert response.status_code == 400


def test_static_stylesheet_is_served() -> None:
    client = TestClient(create_app())

    response = client.get("/static/app.css")

    assert response.status_code == 200
    assert "--sev-high" in response.text


def test_scan_without_key_is_gated() -> None:
    # Hard gate: scanning needs a configured key (VirusTotal has no anonymous access).
    fake = FakeKeyring()  # no key
    client = TestClient(create_app(keyring_module=fake))

    response = client.post("/scan", data={"folder": "/", "upload_eligible": "false"})

    assert response.status_code == 400
    assert "API key is required" in response.text


class _FakeVTClient:
    """Stub VT client injected via engine_factory: every hash is unknown to VT,
    so the online scan path runs without any network calls."""

    info = EngineInfo(id="virustotal", display_name="VirusTotal", default_per_minute=4)

    def __init__(self, engine_id: str, api_key: str) -> None:
        self.info = EngineInfo(
            id=engine_id, display_name=engine_id.title(), default_per_minute=4
        )
        self.api_key = api_key

    async def get_file_report(self, sha256: str):
        return None

    def metrics_snapshot(self):
        from hscanner.budget import RequestMetrics

        return RequestMetrics.zero()

    async def close(self) -> None:
        return None


async def _scan_and_get_report(app, folder: str) -> tuple:
    """POST /scan, wait for the background job, return (progress_page, report_response)."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        page = await ac.post("/scan", data={"folder": folder, "upload_eligible": "false"})
        assert page.status_code == 200
        job_id = re.search(r'data-job-id="([^"]+)"', page.text).group(1)
        job = app.state.job_manager.get(job_id)
        await job.task  # _run() catches all exceptions, so this never raises
        report = await ac.get(f"/reports/{job.report_id}")
    return page, report


async def test_completed_report_has_export_menu_and_full_detail(tmp_path) -> None:
    script = tmp_path / "tool.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    script.chmod(0o755)
    app = create_app(keyring_module=FakeKeyring("key"), engine_factory=_FakeVTClient)

    _, response = await _scan_and_get_report(app, str(tmp_path))

    assert response.status_code == 200
    assert "Export report" in response.text
    assert "Classification" in response.text
    assert "Outcome" in response.text
    assert "Scan engine" in response.text
    assert "Hash lookup" in response.text
    assert "Upload" in response.text
    assert ">Action<" not in response.text
    assert "Full inventory" not in response.text
    assert "severity spectrum" not in response.text
    assert "JSON reference" in response.text
    assert "/reports/" in response.text


async def test_combined_scan_builds_all_engines_and_labels_report(tmp_path) -> None:
    script = tmp_path / "tool.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    script.chmod(0o755)
    built: list[str] = []

    def factory(engine_id: str, api_key: str) -> _FakeVTClient:
        built.append(engine_id)
        return _FakeVTClient(engine_id, api_key)

    app = create_app(keyring_module=FakeKeyring("key"), engine_factory=factory)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        page = await ac.post(
            "/scan", data={"folder": str(tmp_path), "engine": "combined"}
        )
        job_id = re.search(r'data-job-id="([^"]+)"', page.text).group(1)
        job = app.state.job_manager.get(job_id)
        await job.task
        report = await ac.get(f"/reports/{job.report_id}")

    assert built == ["virustotal", "metadefender"]
    assert "scanned with Combined" in report.text


@pytest.mark.parametrize(
    ("suffix", "media_type"),
    [("json", "application/json"), ("html", "text/html"), ("csv", "text/csv")],
)
async def test_web_downloads_each_format(tmp_path, suffix, media_type) -> None:
    script = tmp_path / "tool.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    script.chmod(0o755)
    app = create_app(keyring_module=FakeKeyring("key"), engine_factory=_FakeVTClient)
    _, report_page = await _scan_and_get_report(app, str(tmp_path))
    match = re.search(rf'href="(/reports/[^\"]+\.{suffix})"', report_page.text)
    assert match is not None

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get(match.group(1))

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(media_type)
    assert "attachment" in response.headers["content-disposition"]


def test_unknown_report_download_is_clear_404() -> None:
    response = TestClient(create_app()).get("/reports/not-a-report.json")
    assert response.status_code == 404
    assert "expired or unavailable" in response.text


async def test_api_key_is_absent_from_web_report_and_downloads(tmp_path) -> None:
    secret = "super-secret-vt-api-key-DO-NOT-PERSIST"
    script = tmp_path / "tool.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    script.chmod(0o755)
    app = create_app(keyring_module=FakeKeyring(secret), engine_factory=_FakeVTClient)
    page, report_page = await _scan_and_get_report(app, str(tmp_path))
    links = re.findall(r'href="(/reports/[^\"]+\.(?:json|html|csv))"', report_page.text)

    assert len(links) == 3
    assert secret not in page.text
    assert secret not in report_page.text
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        for link in links:
            response = await ac.get(link)
            assert secret not in response.text
            headers = "\n".join(f"{name}: {value}" for name, value in response.headers.items())
            assert secret not in headers


async def test_scan_renders_outcome_report_with_navigation(tmp_path) -> None:
    # Executable script -> needs attention; a .txt -> skipped.
    script = tmp_path / "tool.sh"
    script.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    script.chmod(0o755)
    (tmp_path / "notes.txt").write_text("hello\n", encoding="utf-8")

    app = create_app(keyring_module=FakeKeyring("a-key"), engine_factory=_FakeVTClient)
    _, response = await _scan_and_get_report(app, str(tmp_path))

    assert response.status_code == 200
    assert "Triage report" in response.text
    assert "Needs attention" in response.text
    assert "Skipped" in response.text
    assert 'class="report-nav"' in response.text
    assert 'href="#needs-attention"' in response.text
    assert 'href="#skipped"' in response.text
    assert response.text.index('id="needs-attention"') < response.text.index('id="scan-all"')
    assert response.text.index('id="scan-all"') < response.text.index(
        'data-outcome="needs_attention"'
    )
    assert "Upload and scan all unverified" in response.text
    assert 'id="upload-progress"' in response.text
    assert 'id="cancel-upload"' in response.text
    assert 'data-summary-key="needs_attention"' in response.text
    assert "const SECTION_META =" in response.text
    assert "function applyFileUpdate" in response.text
    assert "function ensureSection" in response.text
    assert "batchCancelRequested" in response.text
    assert "batchTerminalReceived" in response.text
    assert "if (batchTerminalReceived) return;" in response.text
    assert "Cancellation requested. Waiting for server confirmation" in response.text
    assert "/scan-unverified/active" in response.text
    assert "/cancel" in response.text
    assert "tool.sh" in response.text
