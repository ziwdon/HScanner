import json
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest

from hscanner.budget import RequestBudget, RequestKind
from hscanner.engines._http import EngineHttpMixin
from hscanner.engines.base import EngineFileReport
from hscanner.errors import ErrorCode, HScannerError
from hscanner.progress import ScanCancelled, ScanController, ScanHooks


def test_engine_file_report_roundtrips_through_json_dict() -> None:
    report = EngineFileReport(
        engine_stats={"malicious": 2, "undetected": 68},
        detections=[{"engine": "ExampleAV", "category": "malicious", "name": "Trojan.X"}],
        permalink="https://example.test/reports/abc123",
        last_analysis_at=1_717_171_717,
        assessment_complete=True,
        raw={"data": {"id": "abc123", "attributes": {"score": 2}}},
    )

    restored = EngineFileReport.from_json_dict(report.to_json_dict())

    assert restored == report


def test_engine_file_report_from_json_dict_normalizes_stats_and_bool() -> None:
    data = json.loads(
        json.dumps(
            {
                "engine_stats": {"malicious": "2"},
                "assessment_complete": 1,
            }
        )
    )

    report = EngineFileReport.from_json_dict(data)

    assert report.engine_stats == {"malicious": 2}
    assert report.assessment_complete is True


def test_engine_file_report_from_json_dict_tolerates_null_collections() -> None:
    data = json.loads(
        json.dumps(
            {
                "engine_stats": None,
                "detections": None,
                "assessment_complete": None,
                "raw": None,
            }
        )
    )

    report = EngineFileReport.from_json_dict(data)

    assert report.engine_stats == {}
    assert report.detections == []
    assert report.assessment_complete is False
    assert report.raw == {}


class _RateLimitMixinHost:
    """Minimal host exposing the EngineHttpMixin against a mock transport."""

    def __init__(
        self,
        transport: httpx.MockTransport,
        *,
        max_retries: int = 0,
        sleep=None,
        hooks: ScanHooks | None = None,
    ) -> None:
        class _Engine(EngineHttpMixin):
            def _headers(self_inner):
                return {"x-apikey": "k"}

        self.engine = _Engine()
        self.engine.api_key = "k"
        self.engine.http = httpx.AsyncClient(transport=transport)
        self.engine.budget = RequestBudget(per_minute=100)
        self.engine.hooks = hooks
        self.engine.max_retries = max_retries
        self.engine.backoff_base = 0.0

        if sleep is None:
            async def sleep(_seconds: float) -> None:
                return None

        self.engine._sleep = sleep
        self.engine.rate_limit_wait_count = 0
        self.engine.rate_limit_wait_seconds = 0.0


async def test_rate_limit_error_carries_retry_after() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(429, headers={"Retry-After": "42"})
    )
    host = _RateLimitMixinHost(transport)
    with pytest.raises(HScannerError) as exc:
        await host.engine._request_with_retry(
            RequestKind.LOOKUP, "GET", "https://example.test/x"
        )
    assert exc.value.code == ErrorCode.ENGINE_RATE_LIMITED
    assert exc.value.retry_after == 42.0
    await host.engine.http.aclose()


async def test_rate_limit_error_retry_after_none_when_absent() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(429))
    host = _RateLimitMixinHost(transport)
    with pytest.raises(HScannerError) as exc:
        await host.engine._request_with_retry(
            RequestKind.LOOKUP, "GET", "https://example.test/x"
        )
    assert exc.value.retry_after is None
    await host.engine.http.aclose()


def test_retry_after_http_date_is_parsed() -> None:
    retry_at = datetime.now(UTC) + timedelta(seconds=120)
    response = httpx.Response(429, headers={"Retry-After": format_datetime(retry_at)})
    host = _RateLimitMixinHost(httpx.MockTransport(lambda request: response))

    delay = host.engine._retry_after_header(response)

    assert delay is not None
    assert 0 < delay <= 120


async def test_oversized_retry_after_raises_without_sleeping() -> None:
    sleeps: list[float] = []

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)

    transport = httpx.MockTransport(
        lambda request: httpx.Response(429, headers={"Retry-After": "86400"})
    )
    host = _RateLimitMixinHost(transport, max_retries=1, sleep=sleep)

    with pytest.raises(HScannerError) as exc:
        await host.engine._request_with_retry(
            RequestKind.LOOKUP, "GET", "https://example.test/x"
        )

    assert exc.value.code == ErrorCode.ENGINE_RATE_LIMITED
    assert exc.value.retry_after == 86400.0
    assert sleeps == []
    await host.engine.http.aclose()


async def test_cancel_during_retry_after_wait_is_honored() -> None:
    controller = ScanController()
    sleeps: list[float] = []

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        controller.cancel()

    transport = httpx.MockTransport(
        lambda request: httpx.Response(429, headers={"Retry-After": "3"})
    )
    host = _RateLimitMixinHost(
        transport,
        max_retries=1,
        sleep=sleep,
        hooks=ScanHooks(controller=controller),
    )

    with pytest.raises(ScanCancelled):
        await host.engine._request_with_retry(
            RequestKind.LOOKUP, "GET", "https://example.test/x"
        )

    assert sleeps == [1.0]
    await host.engine.http.aclose()
