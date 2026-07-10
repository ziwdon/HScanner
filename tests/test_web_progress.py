# tests/test_web_progress.py
import asyncio
import inspect
import json
import re
from pathlib import Path

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from hscanner.engines.base import EngineInfo
from hscanner.models import ScanStatus
from hscanner.progress import EventType, ScanProgressEvent, ScanStage
from hscanner.report import build_scan_report
from hscanner.scanner import OnlineScanOutcome
from hscanner.web.app import create_app
from hscanner.web.jobs import JobManager
from hscanner.web.routes import router, scan_events


def test_app_has_job_manager():
    app = create_app()
    assert isinstance(app.state.job_manager, JobManager)


def test_scan_control_endpoints_run_on_the_application_event_loop():
    app = create_app()
    assert router in [
        route.original_router for route in app.routes if hasattr(route, "original_router")
    ]
    control_paths = {
        "/scan/{job_id}/pause",
        "/scan/{job_id}/resume",
        "/scan/{job_id}/cancel",
    }
    endpoints = {
        route.path: route.endpoint
        for route in router.routes
        if getattr(route, "path", None) in control_paths
    }

    assert endpoints.keys() == control_paths
    assert all(inspect.iscoroutinefunction(endpoint) for endpoint in endpoints.values())


def test_report_page_404_for_unknown_id():
    client = TestClient(create_app())
    response = client.get("/reports/nope")
    assert response.status_code == 404
    assert "expired or unavailable" in response.text


def test_progress_status_lines_are_live_regions():
    template = (
        Path(__file__).parents[1]
        / "src"
        / "hscanner"
        / "web"
        / "templates"
        / "progress.html"
    ).read_text(encoding="utf-8")

    assert 'id="current" class="hint" aria-live="polite"' in template
    assert 'id="eta" class="hint" aria-live="polite"' in template
    assert 'id="notice" class="hint" hidden role="status" aria-live="assertive"' in template


def test_report_download_route_still_matches_with_extension(tmp_path):
    """Guard the route-ordering contract: extensioned URLs must reach the DOWNLOAD handler,
    not the page handler.  The test is genuine: it populates the registry and asserts the
    two routes behave *differently* — which is only true when route ordering is correct.
    """
    app = create_app()
    report = build_scan_report(tmp_path, [], online=True, upload_consent=False)
    app.state.report_registry.put(report)
    client = TestClient(app)

    rid = report.report_id

    # Download route: returns JSON with Content-Disposition attachment.
    dl = client.get(f"/reports/{rid}.json")
    assert dl.status_code == 200
    assert dl.headers["content-type"].startswith("application/json")
    assert "attachment" in dl.headers["content-disposition"]

    # Page route: returns HTML, no Content-Disposition attachment.
    page = client.get(f"/reports/{rid}")
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    assert "attachment" not in page.headers.get("content-disposition", "")

    # Unknown extensioned id still 404s (routed to the download handler, not the page).
    unknown = client.get("/reports/nope.json")
    assert unknown.status_code == 404
    assert "expired or unavailable" in unknown.text


# ---------------------------------------------------------------------------
# Task 7: background POST /scan, control routes, and live progress page
# ---------------------------------------------------------------------------


class _FakeKeyring:
    def get_password(self, service, username):
        return "test-key-xyz"

    def set_password(self, service, username, password):
        pass

    def delete_password(self, service, username):
        pass


class _FastFakeClient:
    info = EngineInfo(id="virustotal", display_name="VirusTotal", default_per_minute=4)

    def __init__(self, engine_id, api_key):
        self.hooks = None

    async def get_file_report(self, sha256):
        from hscanner.engines.base import EngineFileReport

        return EngineFileReport(
            engine_stats={"malicious": 0, "undetected": 9},
            assessment_complete=True,
        )

    async def upload_file(self, path):
        return "a"

    async def wait_for_analysis(self, analysis_id, sha256):
        from hscanner.engines.base import EngineFileReport

        return EngineFileReport(
            engine_stats={"malicious": 0, "undetected": 9},
            assessment_complete=True,
        )

    def metrics_snapshot(self):
        from hscanner.budget import RequestMetrics
        return RequestMetrics.zero()

    async def close(self):
        pass


def _client(tmp_path):
    app = create_app(keyring_module=_FakeKeyring(), engine_factory=_FastFakeClient)
    return TestClient(app), app


def _scan_folder(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    return str(root)


def _read_sse(stream: str) -> list[dict[str, object]]:
    return [
        json.loads(line.removeprefix("data: "))
        for line in stream.splitlines()
        if line.startswith("data: ")
    ]


def _event_stream(app, job_id: str):
    response = scan_events(Request({"type": "http", "app": app}), job_id)
    return response.body_iterator


def test_post_scan_returns_progress_page_with_job_id(tmp_path):
    client, app = _client(tmp_path)
    folder = _scan_folder(tmp_path)
    response = client.post("/scan", data={"folder": folder, "upload_eligible": "false"})
    assert response.status_code == 200
    assert "EventSource" in response.text
    assert re.search(r"/scan/[\w-]+/events", response.text)


def test_progress_page_renders_engine_display_mapping(tmp_path):
    client, _ = _client(tmp_path)
    response = client.post("/scan", data={"folder": _scan_folder(tmp_path)})
    assert response.status_code == 200
    assert '"virustotal": "VirusTotal"' in response.text
    assert '"metadefender": "MetaDefender"' in response.text
    assert "current_engine_id" in response.text


def test_progress_page_eta_formatter_has_required_boundaries(tmp_path):
    client, _ = _client(tmp_path)
    response = client.post("/scan", data={"folder": _scan_folder(tmp_path)})
    assert response.status_code == 200
    body = response.text
    assert "seconds < 60" in body
    assert "seconds < 3600" in body
    assert "Math.ceil(seconds) + 's'" in body
    assert "Math.ceil(seconds / 60) + ' min'" in body
    assert "Math.ceil(seconds / 360) / 10" in body


def test_progress_page_uses_outcome_metrics(tmp_path):
    client, _ = _client(tmp_path)
    response = client.post("/scan", data={"folder": _scan_folder(tmp_path)})

    assert response.status_code == 200
    assert 'id="t-scanned"' in response.text
    assert 'id="t-infected"' in response.text
    assert 'id="t-needs-attention"' in response.text
    assert 'id="t-skipped"' in response.text
    assert 'id="t-no-detections"' not in response.text
    assert 'id="t-unknown"' not in response.text


async def test_second_scan_while_active_is_refused(tmp_path):
    app = create_app(keyring_module=_FakeKeyring(), engine_factory=_FastFakeClient)
    # Make the active job block so the second POST sees it as active.
    job = app.state.job_manager.start(_blocking_factory(), lambda o: "r", per_minute=4)
    folder = _scan_folder(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post(
            "/scan", data={"folder": folder, "upload_eligible": "false"}
        )
    assert response.status_code == 409
    assert "already in progress" in response.text
    assert not (tmp_path / "root" / ".hscanner").exists()
    job.cancel()  # signal the blocking factory to exit on its next checkpoint
    await job.task


def _blocking_factory():
    async def factory(observer, controller):
        for _ in range(1000):
            await controller.checkpoint()  # exits when cancelled (raises ScanCancelled)
            await asyncio.sleep(0.01)
        return OnlineScanOutcome(results=[], status=ScanStatus.COMPLETED)
    return factory


def test_control_routes_unknown_id_404(tmp_path):
    client, app = _client(tmp_path)
    assert client.post("/scan/nope/pause").status_code == 404
    assert client.post("/scan/nope/resume").status_code == 404
    assert client.post("/scan/nope/cancel").status_code == 404


async def test_pause_resume_cancel_return_status(tmp_path):
    app = create_app(keyring_module=_FakeKeyring(), engine_factory=_FastFakeClient)
    job = app.state.job_manager.start(_blocking_factory(), lambda o: "r", per_minute=4)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        assert (await ac.post(f"/scan/{job.id}/pause")).json()["status"] == "paused"
        assert (await ac.post(f"/scan/{job.id}/resume")).json()["status"] == "running"
        result = (await ac.post(f"/scan/{job.id}/cancel")).json()["status"]
        assert result in ("running", "cancelled")
    job.cancel()


async def test_scan_events_replay_snapshot_finish_and_exclude_api_key(tmp_path):
    app = create_app(keyring_module=_FakeKeyring(), engine_factory=_FastFakeClient)
    folder = _scan_folder(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        scan_response = await ac.post(
            "/scan", data={"folder": folder, "upload_eligible": "false"}
        )
        match = re.search(r"/scan/([\w-]+)/events", scan_response.text)
        assert match is not None

        response = await ac.get(f"/scan/{match.group(1)}/events")

    events = _read_sse(response.text)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert events[0]["type"] == "snapshot"
    assert any(event["type"] == "scan_finished" for event in events)
    assert "test-key-xyz" not in response.text


@pytest.mark.parametrize("status", [ScanStatus.QUOTA_EXHAUSTED, ScanStatus.AUTH_FAILED])
async def test_late_subscriber_receives_underlying_terminal_scan_status(status):
    async def scan(observer, controller):
        return OnlineScanOutcome(results=[], status=status)

    app = create_app()
    job = app.state.job_manager.start(scan, lambda outcome: "report-late", per_minute=4)
    await job.task

    stream = _event_stream(app, job.id)
    assert _read_sse(await anext(stream))[0]["type"] == "snapshot"
    terminal = _read_sse(await anext(stream))[0]

    assert terminal["status"] == status.value
    assert terminal["report_id"] == "report-late"


def test_scan_events_unknown_id_404(tmp_path):
    client, _ = _client(tmp_path)
    response = client.get("/scan/nope/events")
    assert response.status_code == 404
    assert response.json() == {"error": "unknown job"}


async def test_live_scan_finished_waits_for_final_report_id():
    release = asyncio.Event()
    consumed = asyncio.Event()

    class SignallingQueue(asyncio.Queue):
        async def get(self):
            item = await super().get()
            consumed.set()
            return item

        def get_nowait(self):
            item = super().get_nowait()
            consumed.set()
            return item

    async def scan(observer, controller):
        await release.wait()
        observer(ScanProgressEvent(type=EventType.SCAN_FINISHED, status="completed"))
        await consumed.wait()
        return OnlineScanOutcome(results=[], status=ScanStatus.COMPLETED)

    app = create_app()
    job = app.state.job_manager.start(scan, lambda outcome: "report-live", per_minute=4)
    queue = SignallingQueue()

    def subscribe():
        job._subscribers.add(queue)
        return queue

    job.subscribe = subscribe
    stream = _event_stream(app, job.id)
    assert _read_sse(await anext(stream))[0]["type"] == "snapshot"

    release.set()
    terminal = _read_sse(await asyncio.wait_for(anext(stream), timeout=1))[0]

    assert terminal["type"] == "scan_finished"
    assert terminal["status"] == "completed"
    assert terminal["report_id"] == "report-live"
    with pytest.raises(StopAsyncIteration):
        await asyncio.wait_for(anext(stream), timeout=1)
    assert queue not in job._subscribers


async def test_live_scan_error_synthesizes_credential_safe_terminal_event():
    waiting = asyncio.Event()

    class WaitingQueue(asyncio.Queue):
        async def get(self):
            waiting.set()
            return await super().get()

    async def scan(observer, controller):
        await waiting.wait()
        raise RuntimeError("traceback contains test-key-xyz")

    app = create_app()
    job = app.state.job_manager.start(scan, lambda outcome: "unused", per_minute=4)
    queue = WaitingQueue()

    def subscribe():
        job._subscribers.add(queue)
        return queue

    job.subscribe = subscribe
    stream = _event_stream(app, job.id)
    assert _read_sse(await anext(stream))[0]["type"] == "snapshot"

    terminal = _read_sse(await asyncio.wait_for(anext(stream), timeout=1))[0]

    assert terminal["type"] == "scan_finished"
    assert terminal["status"] == "error"
    assert terminal["error"] == "Internal error"
    serialized = json.dumps(terminal)
    assert "test-key-xyz" not in serialized
    assert "RuntimeError" not in serialized
    assert "traceback" not in serialized.lower()
    with pytest.raises(StopAsyncIteration):
        await asyncio.wait_for(anext(stream), timeout=1)
    assert not queue._getters
    assert queue not in job._subscribers


async def test_full_subscriber_queue_cannot_drop_terminal_completion():
    waiting = asyncio.Event()

    class BoundedWaitingQueue(asyncio.Queue):
        async def get(self):
            waiting.set()
            return await super().get()

    async def scan(observer, controller):
        await waiting.wait()
        observer(ScanProgressEvent(type=EventType.FILE_STARTED, path="a.sh"))
        observer(
            ScanProgressEvent(
                type=EventType.SCAN_FINISHED,
                status=ScanStatus.QUOTA_EXHAUSTED.value,
            )
        )
        return OnlineScanOutcome(results=[], status=ScanStatus.QUOTA_EXHAUSTED)

    app = create_app()
    job = app.state.job_manager.start(scan, lambda outcome: "report-full", per_minute=4)
    queue = BoundedWaitingQueue(maxsize=1)

    def subscribe():
        job._subscribers.add(queue)
        return queue

    job.subscribe = subscribe
    stream = _event_stream(app, job.id)
    assert _read_sse(await anext(stream))[0]["type"] == "snapshot"
    assert _read_sse(await asyncio.wait_for(anext(stream), timeout=1))[0]["type"] == "file_started"

    terminal = _read_sse(await asyncio.wait_for(anext(stream), timeout=1))[0]

    assert terminal["type"] == "scan_finished"
    assert terminal["status"] == ScanStatus.QUOTA_EXHAUSTED.value
    assert terminal["report_id"] == "report-full"
    with pytest.raises(StopAsyncIteration):
        await asyncio.wait_for(anext(stream), timeout=1)
    assert queue not in job._subscribers


# ---------------------------------------------------------------------------
# Task D-fix-2: SSE status field + progress page improvements
# ---------------------------------------------------------------------------


async def test_snapshot_payload_carries_running_status():
    """Snapshot SSE message must include status=='running' for an active job."""
    app = create_app()
    job = app.state.job_manager.start(_blocking_factory(), lambda o: "r", per_minute=4)

    stream = _event_stream(app, job.id)
    snapshot = _read_sse(await anext(stream))[0]

    assert snapshot["type"] == "snapshot"
    assert snapshot["status"] == "running"

    job.cancel()
    await job.task


async def test_snapshot_payload_carries_paused_status():
    """Snapshot SSE message must include status=='paused' when the job is paused."""
    app = create_app()
    job = app.state.job_manager.start(_blocking_factory(), lambda o: "r", per_minute=4)
    job.pause()

    stream = _event_stream(app, job.id)
    snapshot = _read_sse(await anext(stream))[0]

    assert snapshot["type"] == "snapshot"
    assert snapshot["status"] == "paused"

    job.cancel()
    await job.task


async def test_live_event_carries_running_status():
    """Non-terminal live SSE events must include status=='running'."""
    waiting = asyncio.Event()

    async def scan(observer, controller):
        await waiting.wait()
        observer(ScanProgressEvent(type=EventType.FILE_STARTED, path="a.sh"))
        # keep the task alive so the stream can read the live event
        for _ in range(200):
            await controller.checkpoint()
            await asyncio.sleep(0.01)
        return OnlineScanOutcome(results=[], status=ScanStatus.COMPLETED)

    app = create_app()
    job = app.state.job_manager.start(scan, lambda o: "r", per_minute=4)

    stream = _event_stream(app, job.id)
    snapshot = _read_sse(await anext(stream))[0]
    assert snapshot["status"] == "running"

    # signal the scan to emit an event now that our subscriber queue is set up
    waiting.set()
    live = _read_sse(await asyncio.wait_for(anext(stream), timeout=2))[0]
    assert live["type"] == "file_started"
    assert live["status"] == "running"

    job.cancel()
    await job.task


async def test_live_event_carries_paused_status():
    """Non-terminal live SSE events must include the current job status."""
    waiting = asyncio.Event()

    async def scan(observer, controller):
        await waiting.wait()
        observer(ScanProgressEvent(type=EventType.FILE_STARTED, path="b.sh"))
        for _ in range(200):
            await controller.checkpoint()
            await asyncio.sleep(0.01)
        return OnlineScanOutcome(results=[], status=ScanStatus.COMPLETED)

    app = create_app()
    job = app.state.job_manager.start(scan, lambda o: "r", per_minute=4)
    job.pause()

    stream = _event_stream(app, job.id)
    snapshot = _read_sse(await anext(stream))[0]
    assert snapshot["status"] == "paused"

    waiting.set()
    live = _read_sse(await asyncio.wait_for(anext(stream), timeout=2))[0]
    assert live["type"] == "file_started"
    assert live["status"] == "paused"

    job.cancel()
    await job.task


def test_progress_page_tiles_show_outcome_counts(tmp_path):
    """Progress page renders the same outcome metrics as the final report."""
    client, _ = _client(tmp_path)
    folder = _scan_folder(tmp_path)
    response = client.post("/scan", data={"folder": folder, "upload_eligible": "false"})
    assert response.status_code == 200
    # tile labels
    assert "processed" in response.text.lower()
    assert "scanned" in response.text.lower()
    assert "infected" in response.text.lower()
    assert "needs attention" in response.text.lower()
    assert "uploaded" in response.text.lower()
    assert "skipped" in response.text.lower()
    assert "errors" in response.text.lower()
    # tile CSS classes
    assert "tiles" in response.text
    assert "tile alert" in response.text


def test_progress_page_has_status_sync_js_hooks(tmp_path):
    """Progress page JS must include applyStatus, ev.status, ev.error, and response-OK check."""
    client, _ = _client(tmp_path)
    folder = _scan_folder(tmp_path)
    response = client.post("/scan", data={"folder": folder, "upload_eligible": "false"})
    assert response.status_code == 200
    assert "applyStatus" in response.text
    assert "ev.status" in response.text
    assert "ev.error" in response.text
    assert "response.ok" in response.text


def test_progress_page_has_notice_element(tmp_path):
    """Progress page must have a dedicated notice element for control/terminal messages."""
    client, _ = _client(tmp_path)
    folder = _scan_folder(tmp_path)
    response = client.post("/scan", data={"folder": folder, "upload_eligible": "false"})
    assert response.status_code == 200
    assert 'id="notice"' in response.text


def test_progress_page_has_onerror_handling(tmp_path):
    """Progress page JS must include an onerror handler with a credential-safe notice string."""
    client, _ = _client(tmp_path)
    folder = _scan_folder(tmp_path)
    response = client.post("/scan", data={"folder": folder, "upload_eligible": "false"})
    assert response.status_code == 200
    # onerror handler must be present
    assert "onerror" in response.text
    # static, credential-safe notice string shown when the job is unknown/expired
    assert "no longer available" in response.text


async def test_live_sse_payload_carries_current_path_and_stage():
    """SSE live events must include current_path (FILE_STARTED) and current_stage (STAGE_CHANGED)
    from the merged snapshot so the progress page can display them on reconnect."""
    go = asyncio.Event()
    after_file = asyncio.Event()

    async def scan(observer, controller):
        await go.wait()
        observer(ScanProgressEvent(type=EventType.FILE_STARTED, path="live.sh"))
        await after_file.wait()  # hold until the test has read the FILE_STARTED event
        observer(ScanProgressEvent(
            type=EventType.STAGE_CHANGED,
            stage=ScanStage.LOOKUP,
            engine_id="virustotal",
        ))
        for _ in range(200):
            await controller.checkpoint()
            await asyncio.sleep(0.01)
        return OnlineScanOutcome(results=[], status=ScanStatus.COMPLETED)

    app = create_app()
    job = app.state.job_manager.start(scan, lambda o: "r", per_minute=4)
    stream = _event_stream(app, job.id)

    snapshot = _read_sse(await anext(stream))[0]
    assert snapshot["type"] == "snapshot"

    go.set()  # let the scan emit FILE_STARTED
    live1 = _read_sse(await asyncio.wait_for(anext(stream), timeout=2))[0]
    assert live1["type"] == "file_started"
    assert live1["current_path"] == "live.sh"

    after_file.set()  # let the scan emit STAGE_CHANGED
    live2 = _read_sse(await asyncio.wait_for(anext(stream), timeout=2))[0]
    assert live2["type"] == "stage_changed"
    assert live2["current_stage"] == "lookup"
    assert live2["current_engine_id"] == "virustotal"

    job.cancel()
    await job.task
