import asyncio

import pytest

from hscanner.progress import (
    EventType,
    ScanCancelled,
    ScanController,
    ScanHooks,
    ScanProgressEvent,
    ScanStage,
)


def test_event_as_dict_drops_none_and_stringifies_enums():
    event = ScanProgressEvent(
        type=EventType.STAGE_CHANGED, index=2, stage=ScanStage.LOOKUP
    )
    assert event.as_dict() == {"type": "stage_changed", "index": 2, "stage": "lookup"}


def test_controller_starts_unpaused_and_checkpoint_returns():
    controller = ScanController()
    assert controller.paused is False
    asyncio.run(controller.checkpoint())  # does not block, does not raise


async def test_checkpoint_blocks_while_paused_then_resumes():
    controller = ScanController()
    controller.pause()
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(controller.checkpoint(), timeout=0.05)
    controller.resume()
    await asyncio.wait_for(controller.checkpoint(), timeout=0.05)  # unblocked


async def test_cancel_makes_checkpoint_raise_even_if_paused():
    controller = ScanController()
    controller.pause()
    controller.cancel()
    assert controller.cancelled is True
    with pytest.raises(ScanCancelled):
        await asyncio.wait_for(controller.checkpoint(), timeout=0.05)


async def test_hooks_on_wait_emits_stage_event():
    events = []
    hooks = ScanHooks(observer=events.append, controller=ScanController())
    hooks.on_wait(12.0, ScanStage.WAITING_RATE_LIMIT)
    await hooks.checkpoint()  # delegates to controller, returns
    assert events == [
        ScanProgressEvent(type=EventType.STAGE_CHANGED, stage=ScanStage.WAITING_RATE_LIMIT)
    ]


def test_event_serializes_engine_id_when_set():
    from hscanner.progress import EventType, ScanProgressEvent

    ev = ScanProgressEvent(type=EventType.FILE_FINISHED, index=0, engine_id="virustotal")
    assert ev.as_dict()["engine_id"] == "virustotal"


def test_event_omits_engine_id_when_none():
    from hscanner.progress import EventType, ScanProgressEvent

    ev = ScanProgressEvent(type=EventType.FILE_FINISHED, index=0)
    assert "engine_id" not in ev.as_dict()


def test_finished_event_serializes_outcome_facts():
    ev = ScanProgressEvent(
        type=EventType.FILE_FINISHED,
        outcome="infected",
        outcome_reason="engine_detection",
        lookup_status="found",
        upload_status="not_uploaded",
    )

    assert ev.as_dict() == {
        "type": "file_finished",
        "outcome": "infected",
        "outcome_reason": "engine_detection",
        "lookup_status": "found",
        "upload_status": "not_uploaded",
    }
