# tests/test_file_scan_manager.py
import asyncio

import pytest

from hscanner.web.jobs import FileScanManager, JobBusy


@pytest.mark.asyncio
async def test_runs_and_completes():
    mgr = FileScanManager(job_scan_guard=lambda: False)

    async def factory():
        return "RESULT"

    job = mgr.enqueue("rep", 0, factory)
    await job.task
    assert job.state == "done"
    assert job.result == "RESULT"


@pytest.mark.asyncio
async def test_refuses_during_folder_scan():
    mgr = FileScanManager(job_scan_guard=lambda: True)
    with pytest.raises(JobBusy):
        mgr.enqueue("rep", 0, lambda: asyncio.sleep(0))


@pytest.mark.asyncio
async def test_duplicate_returns_existing_job():
    mgr = FileScanManager(job_scan_guard=lambda: False)
    started = asyncio.Event()

    async def factory():
        started.set()
        await asyncio.sleep(0.05)
        return "R"

    a = mgr.enqueue("rep", 1, factory)
    b = mgr.enqueue("rep", 1, factory)
    assert a is b
    await a.task


@pytest.mark.asyncio
async def test_error_sets_state():
    mgr = FileScanManager(job_scan_guard=lambda: False)

    async def boom():
        raise ValueError("x")

    job = mgr.enqueue("rep", 2, boom)
    await asyncio.gather(job.task, return_exceptions=True)
    assert job.state == "error"
    assert job.error == "Internal error"
