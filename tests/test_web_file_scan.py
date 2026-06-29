# tests/test_web_file_scan.py
"""
TDD tests for per-file scan endpoints:
  POST   /reports/{id}/files/{index}/scan
  GET    /reports/{id}/files/{index}/scan/events
  POST   /reports/{id}/scan-unverified
"""
import json

from fastapi.testclient import TestClient

from hscanner.classifier import classify_file
from hscanner.engines.base import EngineFileReport, EngineInfo
from hscanner.inventory import record_from_path
from hscanner.models import EngineState, LookupStatus, ReportAction
from hscanner.report import build_scan_report, classify_report_result
from hscanner.scanner import run_local_scan
from hscanner.web.app import create_app

# ---------------------------------------------------------------------------
# Shared fakes
# ---------------------------------------------------------------------------


class _FakeKeyring:
    def get_password(self, service, username):
        return "fake-api-key"

    def set_password(self, *a):
        pass

    def delete_password(self, *a):
        pass


_BENIGN_VT = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 0, "undetected": 60},
            "last_analysis_results": {},
        }
    }
}
_BENIGN_REPORT = EngineFileReport(
    engine_stats={"malicious": 0, "undetected": 60},
    assessment_complete=True,
    raw=_BENIGN_VT,
)


class _FoundClient:
    """Returns a benign found verdict; upload is never called (get_file_report is non-None)."""

    info = EngineInfo(id="virustotal", display_name="VirusTotal", default_per_minute=4)

    async def get_file_report(self, sha256):
        return _BENIGN_REPORT

    async def upload_file(self, path):
        raise AssertionError("upload must not be called when get_file_report is non-None")

    async def close(self):
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_app_and_client(keyring=None, vt_factory=None):
    app = create_app(
        keyring_module=keyring or _FakeKeyring(),
        engine_factory=vt_factory,
    )
    return app, TestClient(app)


def _seed_report(app, scan_dir):
    """Run a local scan on scan_dir and register the report in app.state."""
    results = run_local_scan(scan_dir)
    report = build_scan_report(scan_dir, results, online=True, upload_consent=False)
    app.state.report_registry.put(report)
    return report


def _idx(report, name):
    return next(i for i, f in enumerate(report.files) if f.relative_path == name)


def _parse_sse(body: str) -> list[dict]:
    return [
        json.loads(line.removeprefix("data: "))
        for line in body.splitlines()
        if line.startswith("data: ")
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_file_scan_202_and_sse_reaches_done(tmp_path, monkeypatch):
    """POST a priority unknown file → 202; SSE stream ends with state==done; registry updated."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("HS_API_KEY_VIRUSTOTAL", raising=False)

    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")

    app, client = _make_app_and_client(vt_factory=lambda engine_id, key: _FoundClient())
    report = _seed_report(app, scan_dir)
    idx = _idx(report, "tool.sh")

    # Sanity: priority file starts without an engine verdict.
    assert report.files[idx].outcome == "needs_attention"

    # POST /scan → 202 with a job_id
    resp = client.post(f"/reports/{report.report_id}/files/{idx}/scan")
    assert resp.status_code == 202, resp.text
    assert "job_id" in resp.json()

    # GET /events → drain stream, verify terminal "done" event
    with client.stream("GET", f"/reports/{report.report_id}/files/{idx}/scan/events") as s:
        body = "".join(s.iter_text())

    events = _parse_sse(body)
    states = [e.get("state") for e in events]
    assert "done" in states, f"No 'done' event in SSE stream. States seen: {states!r}"
    terminal = events[-1]
    assert terminal["outcome"] == "no_detections"
    assert terminal["lookup_status"] == "found"
    assert terminal["upload_status"] == "not_uploaded"

    # Registry must be updated: tool.sh was found in VT
    updated = app.state.report_registry.get(report.report_id)
    assert updated is not None
    assert updated.files[idx].outcome == "no_detections"
    assert updated.files[idx].lookup_status == "found"


def test_file_scan_done_event_includes_live_row_payload(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("HS_API_KEY_VIRUSTOTAL", raising=False)

    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")

    app, client = _make_app_and_client(vt_factory=lambda engine_id, key: _FoundClient())
    report = _seed_report(app, scan_dir)
    idx = _idx(report, "tool.sh")

    resp = client.post(f"/reports/{report.report_id}/files/{idx}/scan")
    assert resp.status_code == 202, resp.text
    with client.stream("GET", f"/reports/{report.report_id}/files/{idx}/scan/events") as s:
        events = _parse_sse("".join(s.iter_text()))

    terminal = events[-1]
    assert terminal["state"] == "done"
    assert terminal["file"]["index"] == idx
    assert terminal["file"]["outcome"] == "no_detections"
    assert 'data-index="0"' in terminal["file_card_html"]
    assert "No detections" in terminal["file_card_html"]


def test_combined_report_file_scan_uses_file_provenance_engine(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")
    built: list[str] = []

    def factory(engine_id, key):
        built.append(engine_id)
        return _FoundClient()

    app, client = _make_app_and_client(vt_factory=factory)
    results = run_local_scan(scan_dir)
    results[0].engine_id = "metadefender"
    report = build_scan_report(
        scan_dir,
        results,
        online=True,
        upload_consent=False,
        engine_id="combined",
        engine_name="Combined",
    )
    app.state.report_registry.put(report)

    response = client.post(f"/reports/{report.report_id}/files/0/scan")

    assert response.status_code == 202
    with client.stream(
        "GET", f"/reports/{report.report_id}/files/0/scan/events"
    ) as stream:
        "".join(stream.iter_text())
    assert built == ["metadefender"]


def test_sensitive_file_returns_400(tmp_path, monkeypatch):
    """POST scan for a sensitive file (*.pem) → 400 with reason=='sensitive'."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("HS_API_KEY_VIRUSTOTAL", raising=False)

    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "id_rsa.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\n")

    app, client = _make_app_and_client()
    report = _seed_report(app, scan_dir)
    idx = _idx(report, "id_rsa.pem")

    resp = client.post(f"/reports/{report.report_id}/files/{idx}/scan")
    assert resp.status_code == 400, resp.text
    assert resp.json()["reason"] == "sensitive"


def test_unknown_report_id_returns_404(tmp_path, monkeypatch):
    """POST scan for a non-existent report → 404."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))

    _, client = _make_app_and_client()
    resp = client.post("/reports/no-such-report/files/0/scan")
    assert resp.status_code == 404, resp.text


def test_scan_unverified_returns_expected_indices(tmp_path, monkeypatch):
    """POST scan-unverified returns eligible Needs attention indices."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("HS_API_KEY_VIRUSTOTAL", raising=False)

    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")
    (scan_dir / "readme.txt").write_text("plain text\n")

    app, client = _make_app_and_client()
    report = _seed_report(app, scan_dir)

    resp = client.post(f"/reports/{report.report_id}/scan-unverified")
    assert resp.status_code == 202, resp.text
    data = resp.json()
    assert "indices" in data

    idx_tool = _idx(report, "tool.sh")
    assert idx_tool in data["indices"], (
        f"tool.sh (idx {idx_tool}) should be in scan-unverified indices: {data['indices']}"
    )

    # readme.txt is skipped (in extensions list), not upload-eligible
    idx_txt = _idx(report, "readme.txt")
    assert idx_txt not in data["indices"], (
        f"readme.txt (idx {idx_txt}) must not be in scan-unverified indices"
    )
    assert "job_id" in data


def test_scan_unverified_batch_updates_report_via_single_sse_stream(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("HS_API_KEY_VIRUSTOTAL", raising=False)

    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")

    app, client = _make_app_and_client(vt_factory=lambda engine_id, key: _FoundClient())
    report = _seed_report(app, scan_dir)
    idx = _idx(report, "tool.sh")

    resp = client.post(f"/reports/{report.report_id}/scan-unverified")
    assert resp.status_code == 202, resp.text
    job_id = resp.json()["job_id"]

    with client.stream(
        "GET", f"/reports/{report.report_id}/scan-unverified/{job_id}/events"
    ) as stream:
        events = _parse_sse("".join(stream.iter_text()))

    assert events[-1]["state"] == "done"
    assert events[-1]["summary"]["needs_attention"] == 0
    updated = app.state.report_registry.get(report.report_id)
    assert updated.files[idx].outcome == "no_detections"


def test_scan_unverified_file_done_events_include_live_row_payload(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("HS_API_KEY_VIRUSTOTAL", raising=False)

    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")

    app, client = _make_app_and_client(vt_factory=lambda engine_id, key: _FoundClient())
    report = _seed_report(app, scan_dir)
    resp = client.post(f"/reports/{report.report_id}/scan-unverified")
    assert resp.status_code == 202, resp.text

    with client.stream(
        "GET", f"/reports/{report.report_id}/scan-unverified/{resp.json()['job_id']}/events"
    ) as stream:
        events = _parse_sse("".join(stream.iter_text()))

    file_events = [event for event in events if event.get("state") == "file_done"]
    assert file_events
    assert file_events[-1]["file"]["outcome"] == "no_detections"
    assert "No detections" in file_events[-1]["file_card_html"]


def test_scan_unverified_active_endpoint_exposes_running_batch(tmp_path, monkeypatch):
    import time

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    from hscanner.web.jobs import BatchFileScanJob

    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")
    app, client = _make_app_and_client()
    report = _seed_report(app, scan_dir)
    job = BatchFileScanJob("batch-job-id", report.report_id, [0])
    job.state = "running"
    app.state.batch_file_scan_manager._jobs[job.id] = (time.monotonic(), job)

    active = client.get(f"/reports/{report.report_id}/scan-unverified/active")
    assert active.status_code == 200
    assert active.json()["active"] is True
    assert active.json()["job_id"] == "batch-job-id"


def test_scan_unverified_active_endpoint_exposes_recent_terminal_batch(tmp_path, monkeypatch):
    import time

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    from hscanner.web.jobs import BatchFileScanJob

    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")
    app, client = _make_app_and_client()
    report = _seed_report(app, scan_dir)
    job = BatchFileScanJob("batch-job-id", report.report_id, [0])
    job.emit({"state": "done", "processed": 1, "total": 1})
    app.state.batch_file_scan_manager._jobs[job.id] = (time.monotonic(), job)

    active = client.get(f"/reports/{report.report_id}/scan-unverified/active")

    assert active.status_code == 200
    assert active.json()["active"] is False
    assert active.json()["job_id"] == "batch-job-id"
    assert active.json()["last"]["state"] == "done"


def test_scan_unverified_active_endpoint_returns_200_when_no_batch(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")
    app, client = _make_app_and_client()
    report = _seed_report(app, scan_dir)

    active = client.get(f"/reports/{report.report_id}/scan-unverified/active")

    assert active.status_code == 200
    assert active.json() == {"active": False}


def test_combined_scan_unverified_uses_combined_engine_order(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")
    built: list[str] = []

    def factory(engine_id, key):
        built.append(engine_id)
        return _FoundClient()

    app, client = _make_app_and_client(vt_factory=factory)
    results = run_local_scan(scan_dir)
    report = build_scan_report(
        scan_dir,
        results,
        online=True,
        upload_consent=False,
        engine_id="combined",
        engine_name="Combined",
    )
    app.state.report_registry.put(report)

    resp = client.post(f"/reports/{report.report_id}/scan-unverified")
    assert resp.status_code == 202, resp.text
    with client.stream(
        "GET", f"/reports/{report.report_id}/scan-unverified/{resp.json()['job_id']}/events"
    ) as stream:
        "".join(stream.iter_text())

    assert built == ["virustotal", "metadefender"]


def test_scan_unverified_deduplicates_matching_sha_rows(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "one.sh").write_text("#!/bin/sh\necho same\n")
    (scan_dir / "two.sh").write_text("#!/bin/sh\necho same\n")

    class _CountingFoundClient(_FoundClient):
        def __init__(self):
            self.lookups = 0

        async def get_file_report(self, sha256):
            self.lookups += 1
            return _BENIGN_REPORT

    engine = _CountingFoundClient()
    app, client = _make_app_and_client(vt_factory=lambda engine_id, key: engine)
    report = _seed_report(app, scan_dir)

    resp = client.post(f"/reports/{report.report_id}/scan-unverified")
    assert resp.status_code == 202, resp.text
    with client.stream(
        "GET", f"/reports/{report.report_id}/scan-unverified/{resp.json()['job_id']}/events"
    ) as stream:
        "".join(stream.iter_text())

    updated = app.state.report_registry.get(report.report_id)
    assert engine.lookups == 1
    assert updated.files[_idx(updated, "one.sh")].outcome == "no_detections"
    assert updated.files[_idx(updated, "two.sh")].outcome == "no_detections"


def test_scan_unverified_cancel_endpoint_marks_batch_cancelling(tmp_path, monkeypatch):
    import time

    from hscanner.web.jobs import BatchFileScanJob

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")
    app, client = _make_app_and_client()
    report = _seed_report(app, scan_dir)
    job = BatchFileScanJob("batch-job-id", report.report_id, [0])
    job.state = "running"
    app.state.batch_file_scan_manager._jobs[job.id] = (time.monotonic(), job)

    response = client.post(
        f"/reports/{report.report_id}/scan-unverified/{job.id}/cancel"
    )

    assert response.status_code == 200
    assert response.json()["status"] == "cancelling"
    assert job.cancel_requested is True
    assert job.last_event["state"] == "cancelling"


def test_scan_unverified_cancel_endpoint_does_not_reactivate_terminal_job(tmp_path, monkeypatch):
    import time

    from hscanner.web.jobs import BatchFileScanJob

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")
    app, client = _make_app_and_client()
    report = _seed_report(app, scan_dir)
    job = BatchFileScanJob("batch-job-id", report.report_id, [0])
    job.emit({"state": "done", "processed": 1, "total": 1})
    app.state.batch_file_scan_manager._jobs[job.id] = (time.monotonic(), job)

    response = client.post(
        f"/reports/{report.report_id}/scan-unverified/{job.id}/cancel"
    )

    assert response.status_code == 200
    assert response.json()["terminal"] is True
    assert response.json()["status"] == "done"
    assert job.cancel_requested is False
    assert job.state == "done"
    assert app.state.batch_file_scan_manager.has_active() is False


def test_scan_unverified_cancel_during_current_file_reports_cancelled(tmp_path, monkeypatch):
    import hscanner.web.routes as routes

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")
    app, client = _make_app_and_client(vt_factory=lambda engine_id, key: _FoundClient())
    report = _seed_report(app, scan_dir)

    async def cancel_during_scan(root, relative_path, *args, **kwargs):
        job = app.state.batch_file_scan_manager.active_for_report(report.report_id)
        job.cancel()
        job.emit({"state": "cancelling", "processed": 0, "total": 1})
        kwargs["state_callback"]("polling", "virustotal")
        record = record_from_path(root, relative_path)
        result = run_local_scan(root)[0]
        result.record = record
        result.classification = classify_file(record, routes.load_default_policy())
        result.sha256 = "a" * 64
        result.engine_id = "virustotal"
        result.engine_state = EngineState.FOUND
        result.lookup_status = LookupStatus.FOUND
        result.action = ReportAction.LOOKUP_FOUND
        result.engine_stats = {"malicious": 0, "undetected": 1}
        result.assessment_complete = True
        return classify_report_result(result)

    monkeypatch.setattr(routes, "scan_single_file_with_rotation", cancel_during_scan)

    resp = client.post(f"/reports/{report.report_id}/scan-unverified")
    assert resp.status_code == 202, resp.text
    with client.stream(
        "GET", f"/reports/{report.report_id}/scan-unverified/{resp.json()['job_id']}/events"
    ) as stream:
        events = _parse_sse("".join(stream.iter_text()))

    states = [event.get("state") for event in events]
    assert states[-1] == "cancelled"
    cancelling_index = states.index("cancelling")
    assert "polling" not in states[cancelling_index:]


def test_scan_unverified_refuses_while_other_report_batch_active(tmp_path, monkeypatch):
    import time

    from hscanner.web.jobs import BatchFileScanJob

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    scan_one = tmp_path / "scan-one"
    scan_two = tmp_path / "scan-two"
    scan_one.mkdir()
    scan_two.mkdir()
    (scan_one / "one.sh").write_text("#!/bin/sh\necho one\n")
    (scan_two / "two.sh").write_text("#!/bin/sh\necho two\n")
    app, client = _make_app_and_client(vt_factory=lambda engine_id, key: _FoundClient())
    report_one = _seed_report(app, scan_one)
    report_two = _seed_report(app, scan_two)
    job = BatchFileScanJob("batch-job-id", report_one.report_id, [0])
    job.state = "running"
    app.state.batch_file_scan_manager._jobs[job.id] = (time.monotonic(), job)

    response = client.post(f"/reports/{report_two.report_id}/scan-unverified")

    assert response.status_code == 409


def test_scan_unverified_batch_exception_updates_report_error(tmp_path, monkeypatch):
    import hscanner.web.routes as routes

    async def fail_scan(*args, **kwargs):
        raise RuntimeError("scan failed")

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(routes, "scan_single_file_with_rotation", fail_scan)
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")
    app, client = _make_app_and_client(vt_factory=lambda engine_id, key: _FoundClient())
    report = _seed_report(app, scan_dir)
    idx = _idx(report, "tool.sh")

    resp = client.post(f"/reports/{report.report_id}/scan-unverified")
    assert resp.status_code == 202, resp.text
    with client.stream(
        "GET", f"/reports/{report.report_id}/scan-unverified/{resp.json()['job_id']}/events"
    ) as stream:
        events = _parse_sse("".join(stream.iter_text()))

    assert events[-1]["state"] == "done"
    assert events[-1]["summary"]["errors"] == 1
    updated = app.state.report_registry.get(report.report_id)
    assert updated.files[idx].outcome == "error"
    assert updated.files[idx].outcome_reason == "engine_client_error"


def test_error_file_is_retryable_and_batch_eligible(tmp_path, monkeypatch):
    import hscanner.web.routes as routes

    async def fail_scan(*args, **kwargs):
        raise RuntimeError("scan failed")

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(routes, "scan_single_file_with_rotation", fail_scan)
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")
    app, client = _make_app_and_client(vt_factory=lambda engine_id, key: _FoundClient())
    report = _seed_report(app, scan_dir)
    idx = _idx(report, "tool.sh")

    resp = client.post(f"/reports/{report.report_id}/scan-unverified")
    assert resp.status_code == 202, resp.text
    with client.stream(
        "GET", f"/reports/{report.report_id}/scan-unverified/{resp.json()['job_id']}/events"
    ) as stream:
        "".join(stream.iter_text())

    report_page = client.get(f"/reports/{report.report_id}")
    assert report_page.status_code == 200
    assert 'id="errors"' in report_page.text
    assert f'class="btn btn-scan" data-index="{idx}"' in report_page.text

    retry_batch = client.post(f"/reports/{report.report_id}/scan-unverified")
    assert retry_batch.status_code == 202, retry_batch.text
    assert idx in retry_batch.json()["indices"]


def test_folder_and_file_scan_blocked_while_batch_active(tmp_path, monkeypatch):
    import time

    from hscanner.web.jobs import BatchFileScanJob

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")
    app, client = _make_app_and_client(vt_factory=lambda engine_id, key: _FoundClient())
    report = _seed_report(app, scan_dir)
    idx = _idx(report, "tool.sh")
    job = BatchFileScanJob("batch-job-id", report.report_id, [idx])
    job.state = "running"
    app.state.batch_file_scan_manager._jobs[job.id] = (time.monotonic(), job)

    folder_response = client.post(
        "/scan", data={"folder": str(scan_dir), "bypass_low_risk": "true"}
    )
    file_response = client.post(f"/reports/{report.report_id}/files/{idx}/scan")

    assert folder_response.status_code == 409
    assert file_response.status_code == 409


def test_scan_unverified_unknown_report_returns_404(tmp_path, monkeypatch):
    """POST scan-unverified for a non-existent report → 404."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))

    _, client = _make_app_and_client()
    resp = client.post("/reports/no-such-report/scan-unverified")
    assert resp.status_code == 404, resp.text


def test_folder_scan_blocked_while_file_scan_active(tmp_path, monkeypatch):
    """POST /scan returns 409 when a per-file scan job is active (bidirectional guard)."""
    import time

    from hscanner.web.jobs import FileScanJob

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("HS_API_KEY_VIRUSTOTAL", raising=False)

    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "tool.sh").write_text("#!/bin/sh\necho hello\n")

    app, client = _make_app_and_client(vt_factory=lambda engine_id, key: _FoundClient())

    # Inject a non-terminal FileScanJob directly into the manager
    fake_job = FileScanJob("fake-job-id", "fake-report-id", 0)
    fake_job.state = "uploading"  # non-terminal: not in ("done", "error")
    app.state.file_scan_manager._jobs["fake-job-id"] = (time.monotonic(), fake_job)

    # Folder scan must be refused while file scan is active
    resp = client.post("/scan", data={"folder": str(scan_dir), "bypass_low_risk": "true"})
    assert resp.status_code == 409, resp.text
