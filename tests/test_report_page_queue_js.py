"""
Regression tests for the report page's per-file scan queue *display* (issue #11).

The queue lives in inline JS in ``report.html``; there is no JS test runner, so
these tests serve ``create_app()`` under uvicorn with a slow fake engine and drive
the real page in jsdom via ``tests/js/queue_driver.mjs``. They skip unless ``node``
and the jsdom/eventsource deps are available (``npm --prefix tests/js install``).
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from httpx import ASGITransport

from hscanner.engines.base import EngineFileReport, EngineInfo
from hscanner.web.app import create_app

JS_DIR = Path(__file__).parent / "js"
DRIVER = JS_DIR / "queue_driver.mjs"
NODE = shutil.which("node")


def _js_deps_available() -> bool:
    if NODE is None:
        return False
    probe = subprocess.run(
        [NODE, "--input-type=module", "-e", "await import('jsdom'); await import('eventsource');"],
        cwd=JS_DIR,
        capture_output=True,
        timeout=30,
    )
    return probe.returncode == 0


pytestmark = pytest.mark.skipif(
    not _js_deps_available(),
    reason="node + jsdom/eventsource required (npm --prefix tests/js install)",
)


class _FakeKeyring:
    def get_password(self, service, username):
        return "fake-key"

    def set_password(self, *a):
        pass

    def delete_password(self, *a):
        pass


_BENIGN = EngineFileReport(
    engine_stats={"malicious": 0, "undetected": 60},
    assessment_complete=True,
    raw={"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "undetected": 60}}}},
)

SCAN_SECONDS = 0.8


class _SlowNotFoundEngine:
    """Every hash is unknown; upload + analysis take ~SCAN_SECONDS so clicks can pile up."""

    def __init__(self, engine_id: str, api_key: str) -> None:
        self.info = EngineInfo(
            id=engine_id, display_name=engine_id.title(), default_per_minute=1000
        )

    async def get_file_report(self, sha256):
        return None

    async def upload_file(self, path):
        await asyncio.sleep(SCAN_SECONDS / 2)
        return "analysis-" + Path(path).name

    async def wait_for_analysis(self, analysis_id, sha256):
        await asyncio.sleep(SCAN_SECONDS / 2)
        return _BENIGN

    def metrics_snapshot(self):
        from hscanner.budget import RequestMetrics

        return RequestMetrics.zero()

    async def close(self):
        return None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _LiveServer:
    """Runs create_app() under uvicorn in a thread; pre-scans ``folder`` on startup."""

    def __init__(self, folder: Path, engine_factory=_SlowNotFoundEngine) -> None:
        self.folder = folder
        self.engine_factory = engine_factory
        self.port = _free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.report_id: str | None = None
        self._ready = threading.Event()
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None

    async def _main(self) -> None:
        app = create_app(keyring_module=_FakeKeyring(), engine_factory=self.engine_factory)
        async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            page = await ac.post("/scan", data={"folder": str(self.folder), "engine": "virustotal"})
            job_id = re.search(r'data-job-id="([^"]+)"', page.text).group(1)
            job = app.state.job_manager.get(job_id)
            await job.task
            self.report_id = job.report_id
        config = uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="warning")
        self._server = uvicorn.Server(config)
        self._ready.set()
        await self._server.serve()

    def __enter__(self) -> _LiveServer:
        self._thread = threading.Thread(target=lambda: asyncio.run(self._main()), daemon=True)
        self._thread.start()
        assert self._ready.wait(30), "server did not start"
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                httpx.get(f"{self.base}/reports/{self.report_id}", timeout=1).raise_for_status()
                return self
            except (httpx.HTTPError, OSError):
                time.sleep(0.05)
        raise AssertionError("server never answered")

    def __exit__(self, *exc) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(10)


def _drive(
    server: _LiveServer,
    *,
    clicks: int,
    pre_wait_ms: int,
    start: int = 0,
    cancel_after_ms: int = 0,
) -> list[dict]:
    env = {
        **os.environ,
        "BASE": server.base,
        "REPORT_ID": server.report_id,
        "CLICKS": str(clicks),
        "GAP_MS": "150",
        "PRE_WAIT_MS": str(pre_wait_ms),
        "START": str(start),
        "CANCEL_AFTER_MS": str(cancel_after_ms),
    }
    proc = subprocess.run(
        [NODE, str(DRIVER)], cwd=JS_DIR, env=env, capture_output=True, text=True, timeout=120
    )
    assert proc.returncode == 0, proc.stderr
    return [json.loads(line) for line in proc.stdout.splitlines() if line.startswith("{")]


def _make_folder(tmp_path: Path, n: int = 4) -> Path:
    folder = tmp_path / "root"
    folder.mkdir()
    for i in range(1, n + 1):
        (folder / f"a{i}.py").write_text(f"print({i}, {time.time_ns()})\n", encoding="utf-8")
    return folder


def _counts(rec: dict) -> tuple[int, int]:
    done, total = rec["count"].split(" / ")
    return int(done), int(total)


def _assert_monotone(records: list[dict], max_total: int) -> None:
    """The card must never read done > total, pos > total, or total > the files queued."""
    for rec in records:
        if rec["hidden"]:
            continue
        done, total = _counts(rec)
        assert done <= total, rec
        assert total <= max_total, rec
        pos = re.search(r"\((\d+) of (\d+)\)", rec["title"])
        if pos:
            assert int(pos.group(1)) <= int(pos.group(2)), rec


def _start_server_job(server: _LiveServer, index: int) -> None:
    """Start a per-file scan server-side (as another tab would) before the page loads."""
    response = httpx.post(f"{server.base}/reports/{server.report_id}/files/{index}/scan")
    assert response.status_code == 202, response.text


@pytest.fixture
def state_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))


def test_queue_total_grows_with_each_click(tmp_path, state_home) -> None:
    """Issue #11: the card must show (1 of N) / 0 / N after N clicks, and end at N / N."""
    clicks = 3
    with _LiveServer(_make_folder(tmp_path)) as server:
        # Let reconnectPerFileScans() resolve first so this test isolates the click path.
        records = _drive(server, clicks=clicks, pre_wait_ms=400)

    by_label = {r["label"]: r for r in records}
    for i in range(clicks):
        rec = by_label[f"click:{i}"]
        assert rec["title"] == f"Per-file upload queue (1 of {i + 1})", rec
        assert rec["count"] == f"0 / {i + 1}", rec
        assert rec["detail"].startswith("a1.py"), rec

    final = by_label["final"]
    assert final["detail"] == "Queue complete."
    assert final["count"] == f"{clicks} / {clicks}"
    assert final["bar"] == "100%"

    for rec in records:
        if rec["hidden"]:
            continue
        done, total = _counts(rec)
        assert done <= total, rec
        pos = re.search(r"\((\d+) of (\d+)\)", rec["title"])
        if pos:
            assert int(pos.group(1)) <= int(pos.group(2)), rec


def test_queue_survives_reconnect_probe_racing_first_click(tmp_path, state_home) -> None:
    """Issue #11 (secondary): a click that lands before ``/files/scan/active`` resolves must
    not let the reconnect path reset or double-count the queue."""
    clicks = 3
    with _LiveServer(_make_folder(tmp_path)) as server:
        records = _drive(server, clicks=clicks, pre_wait_ms=0)

    final = records[-1]
    assert final["detail"] == "Queue complete."
    assert final["count"] == f"{clicks} / {clicks}"
    for rec in records:
        if rec["hidden"]:
            continue
        done, total = _counts(rec)
        assert done <= total, rec
        assert total <= clicks, rec


def test_reconnected_job_is_head_of_the_same_queue(tmp_path, state_home) -> None:
    """Issue #11 (reconnect): a server-side in-flight job found on page load is the running
    head of the click queue, so files queued afterwards extend the same (k of N) count."""
    clicks = 2
    with _LiveServer(_make_folder(tmp_path)) as server:
        _start_server_job(server, 0)
        records = _drive(server, clicks=clicks, pre_wait_ms=400, start=1)

    by_label = {r["label"]: r for r in records}
    before = by_label["before"]
    assert before["title"] == "Per-file upload queue (1 of 1)", before
    assert before["count"] == "0 / 1", before
    assert before["detail"].startswith("a1.py"), before
    for i in range(clicks):
        # The head may finish between clicks, so only the total is asserted here.
        rec = by_label[f"click:{i}"]
        assert _counts(rec)[1] == i + 2, rec
        assert rec["title"].endswith(f"of {i + 2})"), rec

    final = by_label["final"]
    assert final["detail"] == "Queue complete."
    assert final["count"] == f"{clicks + 1} / {clicks + 1}"
    _assert_monotone(records, clicks + 1)


def test_click_racing_probe_with_preexisting_job_does_not_wedge_card(tmp_path, state_home) -> None:
    """Issue #11 (reconnect race): with a server job already running, a click that lands before
    ``/files/scan/active`` resolves makes the probe report two jobs; the page must not count
    the click's own job twice, reset mid-queue, or get stuck without "Queue complete."."""
    clicks = 2
    with _LiveServer(_make_folder(tmp_path)) as server:
        _start_server_job(server, 0)
        records = _drive(server, clicks=clicks, pre_wait_ms=0, start=1)

    final = records[-1]
    assert final["detail"] == "Queue complete.", final
    done, total = _counts(final)
    assert done == total, final
    assert clicks <= total <= clicks + 1, final
    _assert_monotone(records, clicks + 1)


def test_cancel_drops_pending_files_from_the_total(tmp_path, state_home) -> None:
    """Cancelling mid-queue discards the pending files, so the card ends at "k / k" for the
    k files that actually ran — not "k / N · Queue complete." at a partial fraction."""
    clicks = 4
    with _LiveServer(_make_folder(tmp_path)) as server:
        # Clicks span ~0.5 s; cancel lands while file 1 (0.8 s scan) is still in flight
        # or has just finished — either way at least one pending file is discarded.
        records = _drive(server, clicks=clicks, pre_wait_ms=400, cancel_after_ms=1)
        time.sleep(SCAN_SECONDS * 1.5)  # give a wrongly-surviving server job time to run
        outcomes = _server_outcomes(server)

    by_label = {r["label"]: r for r in records}
    final = by_label["final"]
    assert final["detail"] == "Queue complete.", final
    done, total = _counts(final)
    assert done == total, final
    assert 1 <= total < clicks, final
    assert final["bar"] == "100%", final
    # Issue #13: pending files are queued on the server, so Cancel must discard them
    # there too — the dropped files stay unscanned rather than running on silently.
    scanned = sum(1 for outcome in outcomes.values() if outcome == "no_detections")
    assert scanned == total, outcomes


def test_header_scanned_count_updates_with_the_tile(tmp_path, state_home) -> None:
    """Issue #12: after a per-file upload completes, the header line
    "N files inventoried · M scanned with …" must move with the Scanned tile."""
    with _LiveServer(_make_folder(tmp_path, 3)) as server:
        records = _drive(server, clicks=1, pre_wait_ms=400)

    by_label = {r["label"]: r for r in records}
    before = by_label["before"]
    assert before["tile_scanned"] == "0", before
    assert "· 0 scanned with" in before["header"], before

    final = by_label["final"]
    assert final["detail"] == "Queue complete.", final
    assert final["tile_scanned"] == "1", final
    assert "3 files inventoried · 1 scanned with" in final["header"], final


REFRESH_DRIVER = JS_DIR / "refresh_driver.mjs"


def _drive_refresh(server: _LiveServer, *, clicks: int, page1_ms: int) -> list[dict]:
    """Click ``clicks`` files on one page, close it after ``page1_ms``, load the report
    again and observe the second page until its queue drains."""
    env = {
        **os.environ,
        "BASE": server.base,
        "REPORT_ID": server.report_id,
        "CLICKS": str(clicks),
        "PAGE1_MS": str(page1_ms),
    }
    proc = subprocess.run(
        [NODE, str(REFRESH_DRIVER)], cwd=JS_DIR, env=env, capture_output=True, text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return [json.loads(line) for line in proc.stdout.splitlines() if line.startswith("{")]


def _server_outcomes(server: _LiveServer) -> dict[str, str]:
    body = httpx.get(f"{server.base}/reports/{server.report_id}.json", timeout=5).json()
    return {f["relative_path"]: f["outcome"] for f in body["files"]}


def test_queued_files_survive_page_refresh(tmp_path, state_home) -> None:
    """Issue #13: files queued with "Scan this file" must still be scanned — and shown as
    queued — after the page is refreshed, not silently dropped with the card at "1 / 1"."""
    clicks = 4
    with _LiveServer(_make_folder(tmp_path, clicks)) as server:
        # Page 1 is closed ~1 s after the clicks: file 1 done or in flight, 2–4 pending.
        records = _drive_refresh(server, clicks=clicks, page1_ms=1000)
        outcomes = _server_outcomes(server)

    by_label = {r["label"]: r for r in records}
    before = by_label["before-refresh"]
    pending_before = [i for i, s in before["statuses"].items() if s == "queued…"]
    assert len(pending_before) >= 2, before

    after = by_label["after-refresh"]
    # Every file that was still queued or uploading when the tab closed is shown as such,
    # with its button disabled, and the card counts all of them.
    unfinished = [i for i, s in before["statuses"].items() if s]
    for i in unfinished:
        assert after["buttons"][i] in ("disabled", "gone"), (i, after)
        if after["buttons"][i] == "disabled":
            assert after["statuses"][i] in ("queued…", "uploading…", "polling…"), (i, after)
    total_after = _counts(after)[1]
    assert total_after >= len(pending_before), after

    final = by_label["final"]
    assert final["detail"] == "Queue complete.", final
    done, total = _counts(final)
    assert done == total == total_after, final
    # And the files actually got scanned.
    assert outcomes == {f"a{i}.py": "no_detections" for i in range(1, clicks + 1)}, outcomes
