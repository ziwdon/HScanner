import re

import pytest
from fastapi import Request
from httpx import ASGITransport, AsyncClient

from hscanner import cli
from hscanner.budget import RequestBudget, RequestMetrics
from hscanner.engines.registry import (
    COMBINED_ENGINE_IDS,
    ENGINES,
    build_engine,
    build_rotation,
    engine_ids,
)
from hscanner.engines.virustotal import VirusTotalEngine
from hscanner.policy.loader import load_default_policy, parse_quota_policy
from hscanner.web import routes
from hscanner.web.app import create_app


def test_virustotal_is_registered() -> None:
    assert "virustotal" in engine_ids()
    assert ENGINES["virustotal"].display_name == "VirusTotal"


def test_metadefender_is_registered() -> None:
    assert "metadefender" in engine_ids()
    assert ENGINES["metadefender"].display_name == "MetaDefender"


def test_build_engine_returns_virustotal_engine() -> None:
    engine = build_engine("virustotal", "secret", http_client=object())

    assert isinstance(engine, VirusTotalEngine)
    assert engine.info.id == "virustotal"


def test_build_engine_forwards_configuration() -> None:
    budget = RequestBudget()
    http_client = object()

    engine = build_engine(
        "virustotal",
        "secret",
        budget=budget,
        poll_timeout=12.5,
        http_client=http_client,
        poll_interval=0.25,
    )

    assert engine.budget is budget
    assert engine.poll_timeout == 12.5
    assert engine.http is http_client
    assert engine.poll_interval == 0.25


def test_build_engine_rejects_unknown_id() -> None:
    with pytest.raises(ValueError, match="^Unknown engine: missing$"):
        build_engine("missing", "secret")


def test_cli_builder_uses_registry(monkeypatch) -> None:
    built = {}
    sentinel = object()
    monkeypatch.setattr(cli, "open_global_store", lambda: object())

    def fake_build_engine(engine_id, api_key, **kwargs):
        built.update(engine_id=engine_id, api_key=api_key, **kwargs)
        return sentinel

    monkeypatch.setattr(cli, "build_engine", fake_build_engine)

    result = cli._build_engine_client(
        "secret", load_default_policy(), max_requests=7, engine_id="virustotal"
    )

    assert result is sentinel
    assert built["engine_id"] == "virustotal"
    assert built["api_key"] == "secret"
    assert built["budget"].max_requests == 7
    assert built["poll_timeout"] == 600


def test_web_builder_uses_registry(monkeypatch) -> None:
    built = {}
    sentinel = object()
    app = create_app()
    request = Request({"type": "http", "app": app})
    quota = parse_quota_policy(load_default_policy())

    def fake_build_engine(engine_id, api_key, **kwargs):
        built.update(engine_id=engine_id, api_key=api_key, **kwargs)
        return sentinel

    monkeypatch.setattr(routes, "build_engine", fake_build_engine)

    result = routes._build_engine_client(
        request, "secret", quota, object(), engine_id="virustotal"
    )

    assert result is sentinel
    assert built["engine_id"] == "virustotal"
    assert built["api_key"] == "secret"
    assert built["budget"].max_requests == quota.per_scan_request_budget
    assert built["poll_timeout"] == quota.polling_timeout_seconds


def test_web_builder_preserves_injected_factory(monkeypatch) -> None:
    sentinel = object()
    app = create_app(engine_factory=lambda engine_id, key: sentinel)
    request = Request({"type": "http", "app": app})
    quota = parse_quota_policy(load_default_policy())

    monkeypatch.setattr(
        routes,
        "build_engine",
        lambda *args, **kwargs: pytest.fail("registry should not be used with an override"),
    )

    assert routes._build_engine_client(request, "secret", quota, object()) is sentinel


class _Keyring:
    def get_password(self, service, username):
        return "secret"


class _EmptyScanEngine:
    hooks = None

    def metrics_snapshot(self):
        return RequestMetrics.zero()

    async def close(self):
        pass


async def test_folder_scan_nested_builder_uses_registry(tmp_path, monkeypatch) -> None:
    built = {}
    engine = _EmptyScanEngine()

    def fake_build_engine(engine_id, api_key, **kwargs):
        built.update(engine_id=engine_id, api_key=api_key, **kwargs)
        return engine

    monkeypatch.setattr(routes, "build_engine", fake_build_engine)
    app = create_app(keyring_module=_Keyring())

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/scan", data={"folder": str(tmp_path)})

    job_id = re.search(r'data-job-id="([^"]+)"', response.text).group(1)
    await app.state.job_manager.get(job_id).task

    assert built["engine_id"] == "virustotal"
    assert built["api_key"] == "secret"
    assert built["budget"].max_requests is None
    assert built["poll_timeout"] == 600


class _Info:
    def __init__(self, engine_id):
        self.id = engine_id


class _FakeEngine:
    def __init__(self, engine_id):
        self.info = _Info(engine_id)


def test_combined_engine_ids_is_priority_order():
    assert COMBINED_ENGINE_IDS == ["virustotal", "metadefender"]


def test_build_rotation_preserves_order_and_threshold():
    engines = [_FakeEngine("virustotal"), _FakeEngine("metadefender")]
    rotation = build_rotation(
        ["virustotal", "metadefender"], engines, wait_threshold=120.0
    )
    assert [slot.engine.info.id for slot in rotation._slots] == [
        "virustotal",
        "metadefender",
    ]
    assert rotation.wait_threshold == 120.0
