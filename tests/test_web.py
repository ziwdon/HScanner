import os
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from hscanner.engines.base import EngineInfo
from hscanner.report import build_scan_report
from hscanner.scanner import run_local_scan
from hscanner.web import app as web_app
from hscanner.web.app import create_app
from hscanner.web.report_store import ReportRegistry


def test_homepage_loads() -> None:
    client = TestClient(create_app())

    response = client.get("/")

    assert response.status_code == 200
    assert "HScanner" in response.text


def test_app_starts_when_persistent_report_store_init_fails(monkeypatch) -> None:
    def fail_init():
        raise OSError("reports.db unavailable")

    monkeypatch.setattr(web_app, "PersistentReportStore", fail_init)

    client = TestClient(web_app.create_app())
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
    assert "Reports are stored locally and expire after 30 days without access." in response.text
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
    assert "0 skipped" in response.text


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


def test_scan_file_path_returns_file_specific_message(tmp_path) -> None:
    fake = FakeKeyring("key")
    target = tmp_path / "sample.txt"
    target.write_text("hello", encoding="utf-8")
    client = TestClient(create_app(keyring_module=fake))

    response = client.post(
        "/scan",
        data={"folder": str(target), "upload_eligible": "false"},
    )

    assert response.status_code == 400
    assert "is a file, not a folder" in response.text


def test_unknown_engine_error_keeps_key_banner_hidden_when_key_exists() -> None:
    fake = FakeKeyring("key")
    client = TestClient(create_app(keyring_module=fake))

    response = client.post(
        "/scan",
        data={"folder": "/", "engine": "unknown", "upload_eligible": "false"},
    )

    assert response.status_code == 400
    assert "Unknown engine" in response.text
    assert "API key required" not in response.text


def test_static_stylesheet_is_served() -> None:
    client = TestClient(create_app())

    response = client.get("/static/app.css")

    assert response.status_code == 200
    assert "--sev-high" in response.text


def test_base_template_does_not_fetch_external_fonts() -> None:
    response = TestClient(create_app()).get("/")

    assert response.status_code == 200
    assert "fonts.googleapis.com" not in response.text
    assert "fonts.gstatic.com" not in response.text
    assert "/static/app.css?v=10" in response.text


def test_export_menu_stacks_above_report_content_below_topbar() -> None:
    response = TestClient(create_app()).get("/static/app.css")

    assert response.status_code == 200
    stylesheet = response.text
    assert ".topbar" in stylesheet and "z-index: 20" in stylesheet
    assert ".report-head-row" in stylesheet and "z-index:10" in stylesheet
    assert ".export-menu[open]" in stylesheet and "z-index:15" in stylesheet
    assert ".export-options" in stylesheet and "z-index:15" in stylesheet


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


class _FailingPersistentStore:
    def put(self, report):
        raise OSError("reports.db unavailable")

    def get(self, report_id):
        raise OSError("reports.db unavailable")

    def list_reports(self):
        raise OSError("reports.db unavailable")


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


async def test_completed_scan_keeps_report_when_persistent_write_fails(tmp_path) -> None:
    script = tmp_path / "tool.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    script.chmod(0o755)
    registry = ReportRegistry(persistent_store=_FailingPersistentStore())
    app = create_app(
        keyring_module=FakeKeyring("key"),
        engine_factory=_FakeVTClient,
        report_registry=registry,
    )

    _, response = await _scan_and_get_report(app, str(tmp_path))

    assert response.status_code == 200
    assert "Triage report" in response.text


async def test_scan_expands_home_and_stores_resolved_root(tmp_path, monkeypatch) -> None:
    home = tmp_path / "home"
    target = home / "Downloads"
    target.mkdir(parents=True)
    script = target / "tool.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    script.chmod(0o755)
    monkeypatch.setenv("HOME", str(home))
    app = create_app(keyring_module=FakeKeyring("key"), engine_factory=_FakeVTClient)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        page = await ac.post("/scan", data={"folder": "~/Downloads"})
        assert page.status_code == 200
        job_id = re.search(r'data-job-id="([^"]+)"', page.text).group(1)
        job = app.state.job_manager.get(job_id)
        await job.task

    report = app.state.report_registry.get(job.report_id)
    assert report is not None
    assert report.root == str(target.resolve())


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


async def test_web_downloads_handle_non_utf8_filename(tmp_path) -> None:
    bad_path = os.fsencode(tmp_path) + b"/evil\xff.txt"
    fd = os.open(bad_path, os.O_WRONLY | os.O_CREAT, 0o644)
    with os.fdopen(fd, "wb") as handle:
        handle.write(b"sample")
    report = build_scan_report(
        tmp_path,
        run_local_scan(tmp_path),
        online=False,
        upload_consent=False,
        report_id_factory=lambda: "surrogate-report",
    )
    app = create_app(report_registry=ReportRegistry())
    app.state.report_registry.put(report)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        html_response = await ac.get("/reports/surrogate-report.html")
        csv_response = await ac.get("/reports/surrogate-report.csv")

    assert html_response.status_code == 200
    assert csv_response.status_code == 200
    assert html_response.content
    assert csv_response.content


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
    assert "const FILE_PATHS =" in response.text
    assert "const BATCH_CANDIDATE_PATHS =" in response.text
    assert "const SECTION_ORDER =" in response.text
    assert "Pinned to report_view._OUTCOME_ORDER" in response.text
    assert "insertBefore" in response.text
    assert "section.hidden = total === 0" in response.text
    assert "function applyFileUpdate" in response.text
    assert "function ensureSection" in response.text
    assert "batchCancelRequested" in response.text
    assert "batchTerminalReceived" in response.text
    assert "if (batchTerminalReceived) return;" in response.text
    assert "Waiting for server confirmation" in response.text
    assert "/scan-unverified/active" in response.text
    assert "/cancel" in response.text
    assert "tool.sh" in response.text


def test_report_view_renders_needs_attention_groups_and_filters(tmp_path):
    from hscanner.classifier import classify_file
    from hscanner.models import (
        ClassificationBucket,
        FileRecord,
        FileResult,
        LookupStatus,
        OutcomeReason,
        ScanOutcome,
    )
    from hscanner.policy.loader import load_default_policy
    from hscanner.report import build_scan_report, classify_report_result

    root = Path("/scan")

    def _needs(name, bucket):
        rec = FileRecord(
            root=root,
            path=root / name,
            size=100,
            mtime_ns=0,
            mode=0o644,
            is_symlink=False,
            is_regular=True,
            is_hidden=False,
        )
        cls = classify_file(rec, load_default_policy())
        cls.bucket = bucket
        res = FileResult(
            record=rec, classification=cls, lookup_status=LookupStatus.NOT_FOUND
        )
        res.outcome = ScanOutcome.NEEDS_ATTENTION
        res.outcome_reason = OutcomeReason.ENGINE_NOT_FOUND
        return classify_report_result(res)

    results = [
        _needs("tool.exe", ClassificationBucket.UPLOAD_CANDIDATE),
        _needs("notes.txt", ClassificationBucket.HASH_ONLY),
    ]
    report = build_scan_report(
        root,
        results,
        online=True,
        upload_consent=False,
        report_id_factory=lambda: "nap-task4-report",
    )
    app = create_app(report_registry=ReportRegistry())
    app.state.report_registry.put(report)

    response = TestClient(app).get("/reports/nap-task4-report")
    body = response.text
    assert '<details class="group" data-group="high"' in body
    assert '<details class="group" data-group="low_risk"' in body
    assert 'class="risk-chips"' in body
    assert 'class="filter-pills"' in body
    assert 'data-filter="all"' in body
    assert 'data-filter="high"' in body
    assert 'data-filter="medium"' in body
    assert 'data-filter="low_risk"' in body


def test_report_view_renders_extension_groups_for_no_detections(tmp_path):
    from hscanner.classifier import classify_file
    from hscanner.models import (
        FileRecord,
        FileResult,
        LookupStatus,
        OutcomeReason,
        ScanOutcome,
    )
    from hscanner.policy.loader import load_default_policy
    from hscanner.report import build_scan_report, classify_report_result

    root = Path("/scan")

    def _no_detections(name):
        rec = FileRecord(
            root=root,
            path=root / name,
            size=100,
            mtime_ns=0,
            mode=0o644,
            is_symlink=False,
            is_regular=True,
            is_hidden=False,
        )
        cls = classify_file(rec, load_default_policy())
        res = FileResult(
            record=rec, classification=cls, lookup_status=LookupStatus.FOUND
        )
        res.outcome = ScanOutcome.NO_DETECTIONS
        res.outcome_reason = OutcomeReason.ENGINE_CLEAN
        res.assessment_complete = True
        return classify_report_result(res)

    results = [
        _no_detections("alpha.exe"),
        _no_detections("beta.exe"),
        _no_detections("gamma.sh"),
        _no_detections("readme"),
    ]
    report = build_scan_report(
        root,
        results,
        online=True,
        upload_consent=False,
        report_id_factory=lambda: "nap-task5-report",
    )
    app = create_app(report_registry=ReportRegistry())
    app.state.report_registry.put(report)

    body = TestClient(app).get("/reports/nap-task5-report").text

    nodet_match = re.search(
        r'<section class="section" id="no-detections".*?</section>',
        body,
        flags=re.DOTALL,
    )
    assert nodet_match is not None, "no-detections section not found"
    nodet_html = nodet_match.group(0)
    assert '<details class="group" data-group="' in nodet_html
    assert "Showing first 500 of" in nodet_html or 'details class="group"' in nodet_html


def test_base_html_references_latest_app_css_cache_buster() -> None:
    from pathlib import Path

    base = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "hscanner"
        / "web"
        / "templates"
        / "base.html"
    )
    text = base.read_text(encoding="utf-8")
    assert "app.css?v=10" in text


# ---------------------------------------------------------------------------
# Task 4: scan-unverified accepts {"target": ...} body to scope by tier.
# ---------------------------------------------------------------------------


def _nap_task4_results():
    """Four needs-attention results: two priority upload-eligible
    (UPLOAD_CANDIDATE), one low_risk upload-eligible (HASH_ONLY), one
    priority-tier but NOT upload-eligible (SUSPICIOUS_UPLOAD_BLOCKED) which
    must remain excluded by the upload-eligibility layer regardless of the
    tier filter. Returns ``(results, root)``."""
    from hscanner.classifier import classify_file
    from hscanner.models import (
        ClassificationBucket,
        FileRecord,
        FileResult,
        LookupStatus,
    )
    from hscanner.policy.loader import load_default_policy
    from hscanner.report import classify_report_result

    root = Path("/scan")

    def _needs(name, bucket, *, upload_eligible=True):
        rec = FileRecord(
            root=root,
            path=root / name,
            size=100,
            mtime_ns=0,
            mode=0o644,
            is_symlink=False,
            is_regular=True,
            is_hidden=False,
        )
        cls = classify_file(rec, load_default_policy())
        cls.bucket = bucket
        res = FileResult(
            record=rec, classification=cls, lookup_status=LookupStatus.NOT_FOUND
        )
        res.classification.upload_eligible = upload_eligible
        return classify_report_result(res)

    results = [
        _needs("prio1.exe", ClassificationBucket.UPLOAD_CANDIDATE),
        _needs("prio2.sh", ClassificationBucket.UPLOAD_CANDIDATE),
        _needs("low1.txt", ClassificationBucket.HASH_ONLY),
        _needs(
            "blocked.exe",
            ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED,
            upload_eligible=False,
        ),
    ]
    return results, root


def _nap_task4_stub_engine():
    """A no-network stub ScanEngine used only to satisfy the batch runner's
    client construction; the runner fails at hashing (phantom files) before any
    engine method is invoked, so these methods are defensive only."""
    from hscanner.engines.base import EngineFileReport, EngineInfo

    class _Stub:
        def __init__(self, engine_id):
            self.info = EngineInfo(
                id=engine_id, display_name="Stub", default_per_minute=4
            )

        async def get_file_report(self, sha256):
            return EngineFileReport(
                engine_stats={"malicious": 0, "undetected": 60},
                assessment_complete=True,
                raw={"data": {}},
            )

        async def upload_file(self, path):
            raise AssertionError("upload must not be called")

        async def close(self):
            pass

    return _Stub


def _nap_task4_app_and_client(monkeypatch, tmp_path):
    """Create an app + TestClient with a stub engine factory, an env-resolved
    VT key, and XDG_STATE_HOME pointed at a tmp path so no real state DB or
    network is touched."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("HS_API_KEY_VIRUSTOTAL", "nap-task4-fake-key")
    stub = _nap_task4_stub_engine()
    app = create_app(
        report_registry=ReportRegistry(),
        engine_factory=lambda engine_id, key: stub(engine_id),
    )
    return app, TestClient(app)


def _nap_task4_report_and_register(app, results, root, report_id):
    report = build_scan_report(
        root,
        results,
        online=True,
        upload_consent=False,
        report_id_factory=lambda: report_id,
    )
    app.state.report_registry.put(report)
    return report


def test_scan_unverified_target_filters_by_tier(tmp_path, monkeypatch):
    results, root = _nap_task4_results()
    app, client = _nap_task4_app_and_client(monkeypatch, tmp_path)
    report = _nap_task4_report_and_register(
        app, results, root, "nap-task4-target-report"
    )

    r = client.post(
        "/reports/nap-task4-target-report/scan-unverified",
        json={"target": "priority"},
    )
    assert r.status_code == 202, r.text
    indices = r.json()["indices"]
    paths = {report.files[i].relative_path for i in indices}
    assert paths == {"prio1.exe", "prio2.sh"}, paths

    # No body -> all three upload-eligible candidates (blocked stays excluded).
    # Use a fresh report id so the active-batch check doesn't return the
    # previous sub-case's running job.
    app2, client2 = _nap_task4_app_and_client(monkeypatch, tmp_path)
    report2 = _nap_task4_report_and_register(
        app2, results, root, "nap-task4-target-all"
    )
    r = client2.post("/reports/nap-task4-target-all/scan-unverified")
    assert r.status_code == 202, r.text
    paths = {report2.files[i].relative_path for i in r.json()["indices"]}
    assert paths == {"prio1.exe", "prio2.sh", "low1.txt"}, paths


def test_scan_unverified_target_low_risk(tmp_path, monkeypatch):
    results, root = _nap_task4_results()
    app, client = _nap_task4_app_and_client(monkeypatch, tmp_path)
    report = _nap_task4_report_and_register(
        app, results, root, "nap-task4-target-low"
    )

    r = client.post(
        "/reports/nap-task4-target-low/scan-unverified",
        json={"target": "low_risk"},
    )
    assert r.status_code == 202, r.text
    indices = r.json()["indices"]
    paths = {report.files[i].relative_path for i in indices}
    assert paths == {"low1.txt"}, paths


def test_scan_unverified_unknown_target_returns_400(tmp_path, monkeypatch):
    results, root = _nap_task4_results()
    app, client = _nap_task4_app_and_client(monkeypatch, tmp_path)
    _nap_task4_report_and_register(
        app, results, root, "nap-task4-target-unknown"
    )

    r = client.post(
        "/reports/nap-task4-target-unknown/scan-unverified",
        json={"target": "weird"},
    )
    assert r.status_code == 400, r.text
    assert "unknown target" in r.json()["error"], r.text


# ---------------------------------------------------------------------------
# Task 5: nested extension subgroups render inside Needs attention tier
# groups; #scan-all gets a data-target driven by the active filter pill.
# ---------------------------------------------------------------------------


def _nap_task5_nested_results():
    """Three needs-attention results: two priority-tier UPLOAD_CANDIDATE
    files (alpha.exe, beta.sh) and one low_risk-tier HASH_ONLY file
    (notes.txt). Returns ``(results, root)``."""
    from hscanner.classifier import classify_file
    from hscanner.models import (
        ClassificationBucket,
        FileRecord,
        FileResult,
        LookupStatus,
        OutcomeReason,
        ScanOutcome,
    )
    from hscanner.policy.loader import load_default_policy
    from hscanner.report import classify_report_result

    root = Path("/scan")

    def _needs(name, bucket):
        rec = FileRecord(
            root=root,
            path=root / name,
            size=100,
            mtime_ns=0,
            mode=0o644,
            is_symlink=False,
            is_regular=True,
            is_hidden=False,
        )
        cls = classify_file(rec, load_default_policy())
        cls.bucket = bucket
        res = FileResult(
            record=rec, classification=cls, lookup_status=LookupStatus.NOT_FOUND
        )
        res.outcome = ScanOutcome.NEEDS_ATTENTION
        res.outcome_reason = OutcomeReason.ENGINE_NOT_FOUND
        return classify_report_result(res)

    results = [
        _needs("alpha.exe", ClassificationBucket.UPLOAD_CANDIDATE),
        _needs("beta.sh", ClassificationBucket.UPLOAD_CANDIDATE),
        _needs("notes.txt", ClassificationBucket.HASH_ONLY),
    ]
    return results, root


def _nap_task5_extract_group_html(body, group_key):
    """Return the inner HTML of the outermost
    ``<details class="group" data-group="{group_key}">`` element by counting
    nested ``<details>`` openings and closings. Returns ``None`` when the
    outer group is not found. Using a depth walk (instead of a naive
    ``.*?</details>`` regex) avoids truncating at the first nested
    subgroup's closing tag.
    """
    m = re.search(
        r'<details class="group" data-group="' + re.escape(group_key) + r'"[^>]*>',
        body,
    )
    if m is None:
        return None
    start = m.end()
    depth = 1
    i = start
    while i < len(body):
        next_open = body.find("<details", i)
        next_close = body.find("</details>", i)
        if next_close == -1:
            return None
        if next_open != -1 and next_open < next_close:
            depth += 1
            i = next_open + len("<details")
        else:
            depth -= 1
            if depth == 0:
                return body[start:next_close]
            i = next_close + len("</details>")
    return None


def test_needs_attention_renders_nested_extension_subgroups(tmp_path):
    results, root = _nap_task5_nested_results()
    report = build_scan_report(
        root,
        results,
        online=True,
        upload_consent=False,
        report_id_factory=lambda: "nap-task5-nested-report",
    )
    app = create_app(report_registry=ReportRegistry())
    app.state.report_registry.put(report)
    body = TestClient(app).get("/reports/nap-task5-nested-report").text

    priority_html = _nap_task5_extract_group_html(body, "high")
    assert priority_html is not None, "high tier group not found"
    assert '<details class="group subgroup" data-subgroup="exe"' in priority_html
    assert '<details class="group subgroup" data-subgroup="sh"' in priority_html

    low_html = _nap_task5_extract_group_html(body, "low_risk")
    assert low_html is not None, "low_risk tier group not found"
    assert '<details class="group subgroup" data-subgroup="txt"' in low_html


def test_scan_all_button_has_data_target_default_all(tmp_path):
    results, root = _nap_task5_nested_results()
    report = build_scan_report(
        root,
        results,
        online=True,
        upload_consent=False,
        report_id_factory=lambda: "nap-task5-button-report",
    )
    app = create_app(report_registry=ReportRegistry())
    app.state.report_registry.put(report)
    body = TestClient(app).get("/reports/nap-task5-button-report").text

    m = re.search(r'<button[^>]*id="scan-all"[^>]*>', body)
    assert m is not None, "#scan-all button not found"
    button_open = m.group(0)
    assert 'data-target="all"' in button_open
    close = body.find("</button>", m.end())
    assert close != -1
    assert "Upload and scan all unverified" in body
