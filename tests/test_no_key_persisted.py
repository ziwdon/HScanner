import json
import re
import sqlite3
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from hscanner.budget import QuotaCounter
from hscanner.cache import CachedEngineResult, EngineCache
from hscanner.engines.base import EngineFileReport
from hscanner.exporters import render_csv, render_html, render_json
from hscanner.report import build_scan_report, report_payload
from hscanner.scanner import run_local_scan
from hscanner.state import ScanState
from hscanner.store import open_global_store, open_scan_store
from hscanner.web.app import create_app
from hscanner.web.persistent_reports import PersistentReportStore

SECRET = "super-secret-vt-api-key-DO-NOT-PERSIST"


def _dump(conn: sqlite3.Connection) -> str:
    return "\n".join(line for line in conn.iterdump())


def test_no_api_key_string_in_either_database(tmp_path):
    # Exercise all three writers, then dump both DBs and assert the key is absent.
    g = open_global_store(base_dir=tmp_path / "g")
    EngineCache(g).put(CachedEngineResult(
        "virustotal", "a" * 64, datetime.now(UTC), 1,
        EngineFileReport(raw={"data": {"id": "x"}}),
    ))
    QuotaCounter(g).record()
    s = open_scan_store(tmp_path / "root")
    st = ScanState(s, tmp_path / "root")
    st.start_or_resume(resume=False)
    st.record_file("f.bin", 1, 1, "a" * 64, "1:2", "hashed")

    global_dump = _dump(g)
    scan_dump = _dump(s)

    # Verify the dumps are non-empty: the written SHA-256 must appear in each DB,
    # proving the writers actually ran before we assert SECRET is absent.
    assert "a" * 64 in global_dump, "global DB is empty — writers did not run"
    assert "a" * 64 in scan_dump, "scan DB is empty — writers did not run"

    assert SECRET not in global_dump
    assert SECRET not in scan_dump


def test_api_key_absent_from_persistent_reports(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "sample.bin").write_bytes(b"sample")
    report = build_scan_report(
        root,
        run_local_scan(root),
        online=False,
        upload_consent=False,
        report_id_factory=lambda: "report-id",
    )
    store = PersistentReportStore(path=tmp_path / "reports.db")

    store.put(report)
    with sqlite3.connect(tmp_path / "reports.db") as conn:
        dump = _dump(conn)

    assert "report-id" in dump
    assert SECRET not in dump


def test_no_api_key_in_report_or_export_formats(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "sample.bin").write_bytes(b"sample")
    report = build_scan_report(
        root,
        run_local_scan(root),
        online=False,
        upload_consent=False,
        report_id_factory=lambda: "report-id",
    )

    payload_text = json.dumps(report_payload(report))
    json_text = render_json(report)
    html_text = render_html(report)
    csv_text = render_csv(report)

    assert SECRET not in payload_text
    assert SECRET not in json_text
    assert SECRET not in html_text
    assert SECRET not in csv_text


async def test_api_key_absent_from_job_snapshot_and_state(tmp_path):
    class FakeKeyring:
        def get_password(self, service: str, username: str) -> str:
            return SECRET

    class CapturingVTClient:
        from hscanner.engines.base import EngineInfo
        info = EngineInfo(id="virustotal", display_name="VirusTotal", default_per_minute=4)

        def __init__(self, api_key: str) -> None:
            self.api_key = api_key

        async def get_file_report(self, sha256: str):
            return None

        async def close(self) -> None:
            return None

    received_keys: list[str] = []
    clients: list[CapturingVTClient] = []

    def client_factory(engine_id: str, api_key: str) -> CapturingVTClient:
        received_keys.append(api_key)
        client = CapturingVTClient(api_key)
        clients.append(client)
        return client

    (tmp_path / "a.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    app = create_app(keyring_module=FakeKeyring(), engine_factory=client_factory)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/scan", data={"folder": str(tmp_path), "upload_eligible": "false"}
        )

    assert response.status_code == 200
    match = re.search(r'data-job-id="([^"]+)"', response.text)
    assert match is not None
    job = app.state.job_manager.get(match.group(1))
    assert job is not None
    assert job.task is not None
    await job.task

    assert received_keys == [SECRET]
    assert len(clients) == 1
    assert clients[0].api_key == SECRET
    blob = repr(job.snapshot.to_dict()) + repr(job.__dict__)
    assert SECRET not in blob


# ---------------------------------------------------------------------------
# Per-file on-demand scan: API key must not appear in any export surface
# ---------------------------------------------------------------------------

_PER_FILE_SECRET = "SECRETKEY12345"

_FOUND_VT = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 0, "undetected": 60},
            "last_analysis_results": {},
        }
    }
}


def test_api_key_absent_after_manual_file_scan(tmp_path, monkeypatch):
    """Drive a per-file on-demand scan through the web app with a recognizable key.

    Assert that the key string _PER_FILE_SECRET is absent from all four
    surfaces that users or downloaders receive:
      - /reports/{id}.json   (JSON export)
      - /reports/{id}.html   (HTML export)
      - /reports/{id}.csv    (CSV export)
      - /reports/{id}        (report page HTML)
    """
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("HS_API_KEY_VIRUSTOTAL", raising=False)

    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    # A shell script → PRIORITY risk tier → upload-eligible → per-file scan allowed
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")

    class _KeyedKeyring:
        def get_password(self, service: str, username: str) -> str:
            return _PER_FILE_SECRET

        def set_password(self, *a) -> None:
            pass

        def delete_password(self, *a) -> None:
            pass

    class _FoundClient:
        """Returns a canned found-verdict; no key string in any response."""

        from hscanner.engines.base import EngineInfo
        info = EngineInfo(id="virustotal", display_name="VirusTotal", default_per_minute=4)

        async def get_file_report(self, sha256: str):  # noqa: ANN201
            return EngineFileReport(
                engine_stats={"malicious": 0, "undetected": 60},
                assessment_complete=True,
                raw=_FOUND_VT,
            )

        async def upload_file(self, path):  # noqa: ANN001, ANN201
            raise AssertionError("upload must not be called when get_file_report is non-None")

        async def close(self) -> None:
            pass

    app = create_app(
        keyring_module=_KeyedKeyring(),
        engine_factory=lambda engine_id, key: _FoundClient(),
    )
    http = TestClient(app)

    # Seed a report so the per-file endpoint can find it
    results = run_local_scan(scan_dir)
    report = build_scan_report(scan_dir, results, online=True, upload_consent=False)
    app.state.report_registry.put(report)

    idx = next(i for i, f in enumerate(report.files) if f.relative_path == "tool.sh")

    # Trigger the per-file scan
    resp = http.post(f"/reports/{report.report_id}/files/{idx}/scan")
    assert resp.status_code == 202, resp.text
    assert "job_id" in resp.json()

    # Drain the SSE stream until we receive a terminal "done" event
    with http.stream("GET", f"/reports/{report.report_id}/files/{idx}/scan/events") as s:
        sse_body = "".join(s.iter_text())

    events = [
        json.loads(line.removeprefix("data: "))
        for line in sse_body.splitlines()
        if line.startswith("data: ")
    ]
    states = [e.get("state") for e in events]
    assert "done" in states, f"No 'done' event in SSE stream. States seen: {states!r}"

    rid = report.report_id

    # Assert the key is absent from every download surface
    json_body = http.get(f"/reports/{rid}.json")
    assert json_body.status_code == 200, json_body.text
    assert _PER_FILE_SECRET not in json_body.text, "API key found in JSON export"

    html_body = http.get(f"/reports/{rid}.html")
    assert html_body.status_code == 200, html_body.text
    assert _PER_FILE_SECRET not in html_body.text, "API key found in HTML export"

    csv_body = http.get(f"/reports/{rid}.csv")
    assert csv_body.status_code == 200, csv_body.text
    assert _PER_FILE_SECRET not in csv_body.text, "API key found in CSV export"

    page_body = http.get(f"/reports/{rid}")
    assert page_body.status_code == 200, page_body.text
    assert _PER_FILE_SECRET not in page_body.text, "API key found in report page HTML"


# ---------------------------------------------------------------------------
# MetaDefender per-file scan: API key must not appear in any export surface
# ---------------------------------------------------------------------------

_PER_FILE_MD_SECRET = "METADEFENDER_SECRET_KEY_67890"

_FOUND_MD = {
    "scan_results": {
        "progress_percentage": 100,
        "total_avs": 30,
        "total_detected_avs": 0,
        "scan_details": {},
    }
}


def test_api_key_absent_after_manual_file_scan_metadefender(tmp_path, monkeypatch):
    """Drive a per-file on-demand scan through the web app with the MetaDefender engine.

    Assert that _PER_FILE_MD_SECRET is absent from all four surfaces that users
    or downloaders receive:
      - /reports/{id}.json   (JSON export)
      - /reports/{id}.html   (HTML export)
      - /reports/{id}.csv    (CSV export)
      - /reports/{id}        (report page HTML)
    """
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("HS_API_KEY_METADEFENDER", raising=False)

    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    # A shell script → PRIORITY risk tier → upload-eligible → per-file scan allowed
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")

    class _MDKeyedKeyring:
        def get_password(self, service: str, username: str) -> str:
            return _PER_FILE_MD_SECRET

        def set_password(self, *a) -> None:
            pass

        def delete_password(self, *a) -> None:
            pass

    class _MDFoundClient:
        """Returns a canned MetaDefender-shaped found-verdict; key string never appears."""

        from hscanner.engines.base import EngineInfo
        info = EngineInfo(id="metadefender", display_name="MetaDefender", default_per_minute=10)

        async def get_file_report(self, sha256: str):  # noqa: ANN201
            return EngineFileReport(
                engine_stats={"malicious": 0, "undetected": 30},
                assessment_complete=True,
                permalink=f"https://metadefender.com/results/hash/{sha256}",
                raw=_FOUND_MD,
            )

        async def upload_file(self, path):  # noqa: ANN001, ANN201
            raise AssertionError("upload must not be called when get_file_report is non-None")

        async def close(self) -> None:
            pass

    app = create_app(
        keyring_module=_MDKeyedKeyring(),
        engine_factory=lambda engine_id, key: _MDFoundClient(),
    )
    http = TestClient(app)

    # Seed a report with engine_id="metadefender" so the per-file endpoint uses that engine.
    results = run_local_scan(scan_dir)
    report = build_scan_report(
        scan_dir, results, online=True, upload_consent=False,
        engine_id="metadefender", engine_name="MetaDefender",
    )
    app.state.report_registry.put(report)

    idx = next(i for i, f in enumerate(report.files) if f.relative_path == "tool.sh")

    # Trigger the per-file scan
    resp = http.post(f"/reports/{report.report_id}/files/{idx}/scan")
    assert resp.status_code == 202, resp.text
    assert "job_id" in resp.json()

    # Drain the SSE stream until we receive a terminal "done" event
    with http.stream("GET", f"/reports/{report.report_id}/files/{idx}/scan/events") as s:
        sse_body = "".join(s.iter_text())

    events = [
        json.loads(line.removeprefix("data: "))
        for line in sse_body.splitlines()
        if line.startswith("data: ")
    ]
    states = [e.get("state") for e in events]
    assert "done" in states, f"No 'done' event in SSE stream. States seen: {states!r}"

    rid = report.report_id

    # Assert the key is absent from every download surface
    json_body = http.get(f"/reports/{rid}.json")
    assert json_body.status_code == 200, json_body.text
    assert _PER_FILE_MD_SECRET not in json_body.text, "MetaDefender API key found in JSON export"

    html_body = http.get(f"/reports/{rid}.html")
    assert html_body.status_code == 200, html_body.text
    assert _PER_FILE_MD_SECRET not in html_body.text, "MetaDefender API key found in HTML export"

    csv_body = http.get(f"/reports/{rid}.csv")
    assert csv_body.status_code == 200, csv_body.text
    assert _PER_FILE_MD_SECRET not in csv_body.text, "MetaDefender API key found in CSV export"

    page_body = http.get(f"/reports/{rid}")
    assert page_body.status_code == 200, page_body.text
    assert _PER_FILE_MD_SECRET not in page_body.text, "MetaDefender API key found in report page"
