import asyncio

import pytest

from hscanner.web.jobs import BatchFileScanManager, JobBusy


@pytest.mark.asyncio
async def test_batch_manager_returns_existing_active_job_for_report():
    started: list[str] = []

    async def runner(job):
        started.append(job.id)
        await asyncio.sleep(0.05)

    manager = BatchFileScanManager(job_scan_guard=lambda: False)
    first = manager.enqueue("report-id", [1, 2], runner)
    second = manager.enqueue("report-id", [1, 2], runner)
    await first.task

    assert first is second
    assert started == [first.id]
    assert manager.active_for_report("report-id") is None


@pytest.mark.asyncio
async def test_batch_manager_refuses_second_active_report():
    ready = asyncio.Event()

    async def runner(job):
        ready.set()
        await asyncio.sleep(0.05)

    manager = BatchFileScanManager(job_scan_guard=lambda: False)
    first = manager.enqueue("report-one", [1], runner)
    await ready.wait()

    with pytest.raises(JobBusy):
        manager.enqueue("report-two", [2], runner)

    await first.task


@pytest.mark.asyncio
async def test_batch_manager_does_not_evict_active_job_at_capacity():
    ready = asyncio.Event()

    async def old_runner(job):
        job.emit({"state": "done"})

    async def runner(job):
        ready.set()
        await asyncio.sleep(0.05)

    manager = BatchFileScanManager(job_scan_guard=lambda: False, max_jobs=1)
    old = manager.enqueue("old-report", [0], old_runner)
    await old.task
    active = manager.enqueue("active-report", [1], runner)
    await ready.wait()

    assert manager.get(active.id) is active
    assert manager.get(old.id) is None

    await active.task


@pytest.mark.asyncio
async def test_batch_job_emits_dict_events_to_subscribers():
    async def runner(job):
        job.emit({"state": "running", "processed": 0})
        job.emit({"state": "done", "processed": 1})

    manager = BatchFileScanManager(job_scan_guard=lambda: False)
    job = manager.enqueue("report-id", [1], runner)
    queue = job.subscribe()
    await job.task

    events = []
    while not queue.empty():
        events.append(queue.get_nowait())
    job.unsubscribe(queue)

    assert any(
        event.get("state") == "running" and event.get("processed") == 0
        for event in events
    )
    assert any(
        event.get("state") == "done" and event.get("processed") == 1
        for event in events
    )
    assert job.is_terminal


@pytest.mark.asyncio
async def test_batch_job_cancel_sets_cancel_requested():
    ready = asyncio.Event()

    async def runner(job):
        ready.set()
        while not job.cancel_requested:
            await asyncio.sleep(0)
        job.emit({"state": "cancelled"})

    manager = BatchFileScanManager(job_scan_guard=lambda: False)
    job = manager.enqueue("report-id", [1], runner)
    await ready.wait()
    job.cancel()
    await job.task

    assert job.cancel_requested is True
    assert job.state == "cancelled"


def test_batch_manager_refuses_when_folder_scan_active():
    manager = BatchFileScanManager(job_scan_guard=lambda: True)

    with pytest.raises(JobBusy):
        manager.enqueue("report-id", [1], lambda job: None)


@pytest.mark.asyncio
async def test_batch_job_replay_history_is_bounded():
    async def runner(job):
        for index in range(250):
            job.emit({"state": "file_done", "processed": index + 1})
        job.emit({"state": "done", "processed": 250})

    manager = BatchFileScanManager(job_scan_guard=lambda: False)
    job = manager.enqueue("report-id", list(range(250)), runner)
    await job.task

    replay = job.replay_events()

    assert len(replay) <= 201
    assert replay[0]["state"] == "snapshot"
    assert replay[0]["last"]["state"] == "done"
    assert replay[-1]["state"] == "done"
