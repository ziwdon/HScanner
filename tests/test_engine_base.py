import json

import httpx
import pytest

from hscanner.budget import RequestBudget, RequestKind
from hscanner.engines._http import EngineHttpMixin
from hscanner.engines.base import EngineFileReport
from hscanner.errors import ErrorCode, HScannerError


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

    def __init__(self, transport: httpx.MockTransport) -> None:
        class _Engine(EngineHttpMixin):
            def _headers(self_inner):
                return {"x-apikey": "k"}

        self.engine = _Engine()
        self.engine.api_key = "k"
        self.engine.http = httpx.AsyncClient(transport=transport)
        self.engine.budget = RequestBudget(per_minute=100)
        self.engine.hooks = None
        self.engine.max_retries = 0
        self.engine.backoff_base = 0.0

        async def _sleep(_seconds: float) -> None:
            return None

        self.engine._sleep = _sleep
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
