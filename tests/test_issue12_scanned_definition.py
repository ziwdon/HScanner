"""
Regression tests for issue #12: "Scanned" must mean one thing everywhere.

``compute_summary`` defines *scanned* as a definitive engine verdict
(``infected`` / ``no_detections``) or a completed upload; the live progress snapshot
(``JobSnapshot``) and the ``/scan/{id}/status`` endpoint must agree with it, so a
hash-only "not found" file counts as *needs attention*, never as *scanned*.
"""
from __future__ import annotations

import asyncio
import re

import pytest
from httpx import ASGITransport, AsyncClient

from hscanner.budget import RequestMetrics
from hscanner.engines.base import EngineInfo
from hscanner.progress import EventType, ScanProgressEvent
from hscanner.report import counts_as_scanned
from hscanner.web.app import create_app
from hscanner.web.jobs import JobSnapshot


def _finished(**fields) -> ScanProgressEvent:
    return ScanProgressEvent(type=EventType.FILE_FINISHED, **fields)


def test_snapshot_does_not_count_hash_lookup_not_found_as_scanned():
    snap = JobSnapshot(per_minute=4)
    snap.apply(ScanProgressEvent(type=EventType.SCAN_STARTED, total=1))
    snap.apply(_finished(
        outcome="needs_attention",
        outcome_reason="not_found",
        lookup_status="not_found",
        upload_status="not_uploaded",
    ))
    payload = snap.to_dict()
    assert payload["scanned"] == 0
    assert payload["needs_attention"] == 1


@pytest.mark.parametrize(
    ("outcome", "lookup_status", "upload_status", "expected"),
    [
        ("no_detections", "found", "not_uploaded", 1),
        ("infected", "found", "not_uploaded", 1),
        ("needs_attention", "not_found", "analysis_complete", 1),
        ("needs_attention", "not_found", "analysis_failed", 0),
        ("needs_attention", "not_found", "uploaded", 0),
        ("error", "error", "not_uploaded", 0),
        ("skipped", "not_checked", "not_uploaded", 0),
    ],
)
def test_snapshot_scanned_uses_the_report_definition(
    outcome, lookup_status, upload_status, expected
):
    snap = JobSnapshot(per_minute=4)
    snap.apply(ScanProgressEvent(type=EventType.SCAN_STARTED, total=1))
    snap.apply(_finished(
        outcome=outcome,
        outcome_reason="x",
        lookup_status=lookup_status,
        upload_status=upload_status,
    ))
    assert snap.to_dict()["scanned"] == expected
    # The snapshot must track the Core's single definition, not a table of its own.
    assert expected == int(counts_as_scanned(outcome, upload_status))


class _FakeKeyring:
    def get_password(self, service, username):
        return "test-key-xyz"

    def set_password(self, service, username, password):
        pass

    def delete_password(self, service, username):
        pass


class _NotFoundEngine:
    """Every hash is unknown to the engine; folder scans never upload."""

    def __init__(self, engine_id, api_key):
        self.info = EngineInfo(
            id=engine_id, display_name=engine_id.title(), default_per_minute=1000
        )

    async def get_file_report(self, sha256):
        return None

    async def upload_file(self, path):
        raise AssertionError("folder scans must not upload")

    async def wait_for_analysis(self, analysis_id, sha256):
        raise AssertionError("folder scans must not poll")

    def metrics_snapshot(self):
        return RequestMetrics.zero()

    async def close(self):
        return None


def test_status_endpoint_scanned_matches_report_summary(tmp_path):
    """Issue #12: a folder of unknown files shows "N scanned" live and "0 scanned" in the
    report. The status endpoint and the report summary must agree."""
    root = tmp_path / "root"
    root.mkdir()
    for i in range(5):
        (root / f"a{i}.py").write_text(f"print({i})\n", encoding="utf-8")
    for i in range(4):
        (root / f"d{i}.txt").write_text("data\n", encoding="utf-8")

    async def run():
        app = create_app(keyring_module=_FakeKeyring(), engine_factory=_NotFoundEngine)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            page = await ac.post("/scan", data={"folder": str(root), "engine": "virustotal"})
            job_id = re.search(r'data-job-id="([^"]+)"', page.text).group(1)
            job = app.state.job_manager.get(job_id)
            await job.task
            status = (await ac.get(f"/scan/{job_id}/status")).json()
            report = (await ac.get(f"/reports/{job.report_id}.json")).json()
            return status, report

    status, report = asyncio.run(run())
    summary = report["summary"]
    assert summary["needs_attention"] == 5
    assert summary["scanned"] == 0
    assert status["scanned"] == summary["scanned"]
    assert status["needs_attention"] == summary["needs_attention"]
