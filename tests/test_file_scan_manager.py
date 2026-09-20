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


@pytest.mark.asyncio
async def test_cancel_pending_drops_queued_jobs_but_not_the_running_one():
    """Issue #13: pending per-file jobs live on the server, so Cancel must be able to
    discard them before they start; the in-flight job is left to finish."""
    mgr = FileScanManager(job_scan_guard=lambda: False)
    release = asyncio.Event()
    ran: list[int] = []

    def factory(i):
        async def run():
            ran.append(i)
            await release.wait()
            return i
        return run

    head = mgr.enqueue("rep", 0, factory(0))
    queued = [mgr.enqueue("rep", i, factory(i)) for i in (1, 2)]
    await asyncio.sleep(0)  # let the head take the lock
    assert head.state == "uploading"
    assert [j.state for j in queued] == ["queued", "queued"]

    cancelled = mgr.cancel_pending("rep")
    assert [j.index for j in cancelled] == [1, 2]
    assert all(j.state == "cancelled" and j.is_terminal for j in queued)
    assert head.state == "uploading"
    assert mgr.active_jobs_for_report("rep") == [head]

    release.set()
    await head.task
    await asyncio.gather(*(j.task for j in queued), return_exceptions=True)
    assert head.state == "done"
    assert ran == [0]
    # A cancelled slot can be queued again.
    again = mgr.enqueue("rep", 1, factory(1))
    assert again is not queued[0]
    await again.task
    assert ran == [0, 1]


@pytest.mark.asyncio
async def test_cancel_pending_only_touches_the_given_report():
    mgr = FileScanManager(job_scan_guard=lambda: False)
    release = asyncio.Event()

    async def wait():
        await release.wait()

    head = mgr.enqueue("rep", 0, wait)
    other = mgr.enqueue("other", 0, wait)
    mine = mgr.enqueue("rep", 1, wait)
    await asyncio.sleep(0)
    assert [j.index for j in mgr.cancel_pending("rep")] == [1]
    assert other.state == "queued"
    assert mine.state == "cancelled"
    release.set()
    await asyncio.gather(head.task, other.task, mine.task, return_exceptions=True)


@pytest.mark.asyncio
async def test_job_cap_never_evicts_a_queued_or_running_job():
    """A burst of clicks beyond max_jobs must not drop a live job from the index —
    /files/scan/active would forget it and a refresh would re-enable its button."""
    mgr = FileScanManager(job_scan_guard=lambda: False, max_jobs=2)
    release = asyncio.Event()

    async def wait():
        await release.wait()

    jobs = [mgr.enqueue("rep", i, wait) for i in range(4)]
    assert mgr.active_jobs_for_report("rep") == jobs
    release.set()
    await asyncio.gather(*(j.task for j in jobs))
    # Once terminal, the cap applies again.
    mgr.enqueue("rep", 9, wait)
    assert len(mgr._jobs) <= 3
    release.set()
