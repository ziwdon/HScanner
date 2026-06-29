import httpx
import pytest

from hscanner.engines.virustotal import VirusTotalEngine
from hscanner.progress import ScanCancelled, ScanStage


class RecordingHooks:
    def __init__(self, *, cancel_after: int | None = None) -> None:
        self.checkpoints = 0
        self.waits: list[tuple[float, str]] = []
        self.cancel_after = cancel_after

    async def checkpoint(self) -> None:
        self.checkpoints += 1
        if self.cancel_after is not None and self.checkpoints > self.cancel_after:
            raise ScanCancelled()

    def on_wait(self, seconds: float, stage: ScanStage) -> None:
        self.waits.append((seconds, str(stage)))


def _mock_transport(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_checkpoint_called_before_and_after_budget_acquisition():
    hooks = RecordingHooks()
    http = _mock_transport(lambda req: httpx.Response(404))
    client = VirusTotalEngine("k", http_client=http, hooks=hooks)
    result = await client.get_file_report("a" * 64)
    await client.close()
    assert result is None
    assert hooks.checkpoints == 2


async def test_cancel_raised_from_checkpoint_propagates():
    hooks = RecordingHooks(cancel_after=0)  # raise on first checkpoint
    http = _mock_transport(lambda req: httpx.Response(404))
    client = VirusTotalEngine("k", http_client=http, hooks=hooks)
    with pytest.raises(ScanCancelled):
        await client.get_file_report("a" * 64)
    await client.close()


async def test_on_wait_emits_polling_stage_between_polls():
    # First analyses poll returns "queued", second returns "completed".
    states = iter(["queued", "completed"])

    def handler(req: httpx.Request) -> httpx.Response:
        if "/analyses/" in str(req.url):
            return httpx.Response(200, json={"data": {"attributes": {"status": next(states)}}})
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {}}}})

    hooks = RecordingHooks()
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    client = VirusTotalEngine(
        "k", http_client=_mock_transport(handler), hooks=hooks, sleep=fake_sleep, poll_interval=15.0
    )
    await client.wait_for_analysis("analysis-1", "a" * 64)
    await client.close()
    assert (15.0, "polling") in hooks.waits
    assert hooks.checkpoints >= 2  # checked before each poll attempt
