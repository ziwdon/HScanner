import asyncio

import httpx
import pytest

from hscanner.budget import RequestBudget, RequestKind
from hscanner.engines.base import EngineFileReport, EngineInfo
from hscanner.engines.virustotal import VirusTotalEngine
from hscanner.errors import ErrorCode, HScannerError
from hscanner.progress import ScanCancelled, ScanController, ScanHooks


@pytest.mark.asyncio
async def test_get_file_report_returns_not_found() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(404, json={"error": {"code": "NotFoundError"}})
    )
    client = VirusTotalEngine("key", http_client=httpx.AsyncClient(transport=transport))

    result = await client.get_file_report("abc")

    assert result is None


@pytest.mark.asyncio
async def test_auth_error_raises_stable_code() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(401, json={"error": {"code": "WrongCredentialsError"}})
    )
    client = VirusTotalEngine("bad", http_client=httpx.AsyncClient(transport=transport))

    with pytest.raises(HScannerError) as exc:
        await client.get_file_report("abc")

    assert exc.value.code == ErrorCode.ENGINE_AUTH_FAILED


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def make_client(handler, **kwargs):
    clock = FakeClock()
    transport = httpx.MockTransport(handler)
    client = VirusTotalEngine(
        "key",
        http_client=httpx.AsyncClient(transport=transport),
        budget=RequestBudget(per_minute=1000, sleep=clock.sleep, monotonic=clock.monotonic),
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        **kwargs,
    )
    return client, clock


@pytest.mark.asyncio
async def test_retries_429_then_succeeds() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, json={})
        return httpx.Response(200, json={"data": {"id": "x"}})

    client, clock = make_client(handler)
    result = await client.get_file_report("abc")
    assert isinstance(result, EngineFileReport)
    assert result.raw == {"data": {"id": "x"}}
    assert calls["n"] == 2
    assert clock.sleeps  # backed off at least once
    assert client.budget.counts[RequestKind.LOOKUP] == 2  # each attempt counted

    metrics = client.metrics_snapshot()
    assert metrics.rate_limit_wait_count == 1
    assert metrics.rate_limit_wait_seconds == 1.0
    assert metrics.total == 2


@pytest.mark.asyncio
async def test_retry_after_is_included_in_rate_limit_metrics() -> None:
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        if calls["count"] == 1:
            return httpx.Response(429, headers={"Retry-After": "3"}, json={})
        return httpx.Response(404, json={})

    client, _ = make_client(handler)
    assert await client.get_file_report("abc") is None

    metrics = client.metrics_snapshot()
    assert metrics.rate_limit_wait_count == 1
    assert metrics.rate_limit_wait_seconds == 3.0


@pytest.mark.asyncio
async def test_429_exhausted_raises_rate_limited() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={})

    client, _ = make_client(handler, max_retries=2)
    with pytest.raises(HScannerError) as exc:
        await client.get_file_report("abc")
    assert exc.value.code == ErrorCode.ENGINE_RATE_LIMITED


@pytest.mark.asyncio
async def test_5xx_exhausted_raises_server_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={})

    client, _ = make_client(handler, max_retries=1)
    with pytest.raises(HScannerError) as exc:
        await client.get_file_report("abc")
    assert exc.value.code == ErrorCode.ENGINE_SERVER_ERROR


@pytest.mark.asyncio
async def test_transport_error_raises_network_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    client, _ = make_client(handler, max_retries=1)
    with pytest.raises(HScannerError) as exc:
        await client.get_file_report("abc")
    assert exc.value.code == ErrorCode.ENGINE_NETWORK_ERROR


@pytest.mark.asyncio
async def test_auth_error_not_retried() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(401, json={})

    client, _ = make_client(handler)
    with pytest.raises(HScannerError) as exc:
        await client.get_file_report("abc")
    assert exc.value.code == ErrorCode.ENGINE_AUTH_FAILED
    assert calls["n"] == 1  # no retry


@pytest.mark.asyncio
async def test_cancel_during_budget_wait_prevents_http_request() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    class BlockingBudget:
        async def acquire(self, kind, *, on_wait=None):
            entered.set()
            await release.wait()

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(404, json={})

    controller = ScanController()
    client = VirusTotalEngine(
        "key",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        budget=BlockingBudget(),
        hooks=ScanHooks(controller=controller),
    )
    request = asyncio.create_task(client.get_file_report("abc"))
    await entered.wait()

    controller.cancel()
    release.set()

    with pytest.raises(ScanCancelled):
        await request
    assert calls == 0
    await client.close()


@pytest.mark.asyncio
async def test_upload_retry_resends_file_body(tmp_path) -> None:
    sample = tmp_path / "tool.sh"
    sample.write_bytes(b"#!/bin/sh\necho hello\n")
    bodies: list[int] = []
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        bodies.append(len(request.content))
        if calls["n"] == 1:
            return httpx.Response(429, json={})
        return httpx.Response(200, json={"data": {"id": "analysis-1"}})

    client, _ = make_client(handler)
    result = await client.upload_file(sample)

    assert calls["n"] == 2                 # retried once
    assert all(size > 0 for size in bodies)  # BOTH attempts carried the file body
    assert result == "analysis-1"


@pytest.mark.asyncio
async def test_wait_for_analysis_polls_until_completed() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/api/v3/analyses/"):
            calls["n"] += 1
            status = "completed" if calls["n"] >= 2 else "queued"
            return httpx.Response(200, json={"data": {"attributes": {"status": status}}})
        # final file re-fetch
        return httpx.Response(
            200,
            json={"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}},
        )

    client, _ = make_client(handler)
    report = await client.wait_for_analysis("aid", "sha")
    assert calls["n"] == 2  # polled twice (queued, then completed)
    assert report.engine_stats == {"malicious": 0}


@pytest.mark.asyncio
async def test_wait_for_analysis_times_out() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"attributes": {"status": "queued"}}})

    client, _ = make_client(handler, poll_interval=15.0, poll_timeout=30.0)
    with pytest.raises(HScannerError) as exc:
        await client.wait_for_analysis("aid", "sha")
    assert exc.value.code == ErrorCode.ANALYSIS_TIMEOUT


def test_normalizes_provider_payload_to_engine_report() -> None:
    payload = {
        "data": {
            "attributes": {
                "last_analysis_date": 1_718_886_000,
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 1,
                    "ignored": "not-an-int",
                },
                "last_analysis_results": {
                    "Zulu": {"category": "malicious", "result": "Trojan.Z"},
                    "Alpha": {"category": "suspicious", "result": None},
                    "Clean": {"category": "undetected", "result": None},
                    "Broken": "not-a-dict",
                },
            }
        }
    }
    engine = VirusTotalEngine.__new__(VirusTotalEngine)

    report = engine._to_report(payload, "abc")

    assert engine.info == EngineInfo("virustotal", "VirusTotal", 4)
    assert report == EngineFileReport(
        engine_stats={"malicious": 1, "suspicious": 1},
        detections=[
            {"engine": "Alpha", "category": "suspicious", "name": "suspicious"},
            {"engine": "Zulu", "category": "malicious", "name": "Trojan.Z"},
        ],
        permalink="https://www.virustotal.com/gui/file/abc",
        last_analysis_at=1_718_886_000,
        assessment_complete=True,
        raw=payload,
    )


def test_completed_analysis_stats_are_normalized() -> None:
    payload = {
        "data": {
            "attributes": {
                "status": "completed",
                "stats": {"malicious": 0, "undetected": 12},
            }
        }
    }

    report = VirusTotalEngine.__new__(VirusTotalEngine)._to_report(payload, "abc")

    assert report.assessment_complete is True
    assert report.engine_stats == {"malicious": 0, "undetected": 12}


def test_empty_last_analysis_stats_falls_back_to_analysis_stats() -> None:
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {},
                "stats": {"malicious": 1},
            }
        }
    }

    report = VirusTotalEngine.__new__(VirusTotalEngine)._to_report(payload, "abc")

    assert report.assessment_complete is True
    assert report.engine_stats == {"malicious": 1}
