import re

from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from hscanner.budget import RequestMetrics
from hscanner.engines.base import EngineInfo
from hscanner.policy.loader import load_default_policy, parse_quota_policy
from hscanner.web.app import create_app


class _NoKeys:
    def get_password(self, *args):
        return None


def test_quota_policy_values_are_available_to_web():
    # Guards the wiring contract: the web layer sources pacing from policy.
    q = parse_quota_policy(load_default_policy())
    assert q.requests_per_minute == 4
    assert q.cache_ttl_days == 30


def test_combined_requires_all_keys(tmp_path):
    client = TestClient(create_app(keyring_module=_NoKeys()))

    response = client.post(
        "/scan", data={"folder": str(tmp_path), "engine": "combined"}
    )

    assert response.status_code == 400
    assert "API key is required for:" in response.text


def test_include_subfolders_false_echoed_on_validation_error(tmp_path):
    class _Keys:
        def get_password(self, *args):
            return "KEY"
    client = TestClient(create_app(keyring_module=_Keys()))
    # Non-existent folder forces the validation-error re-render path.
    response = client.post(
        "/scan",
        data={
            "folder": "/does/not/exist",
            "engine": "virustotal",
            "include_subfolders": "false",
        },
    )
    assert response.status_code == 400
    # The checkbox is present and NOT checked: find the input tag that
    # contains name="include_subfolders" and confirm "checked" is absent
    # from that single tag (the guard evaluated false because the value
    # was echoed as False).
    start = response.text.find("<input")
    while start != -1:
        end = response.text.find(">", start)
        tag = response.text[start : end if end != -1 else None]
        if 'name="include_subfolders"' in tag:
            assert "checked" not in tag
            return
        start = response.text.find("<input", end if end != -1 else start + 1)
    raise AssertionError("include_subfolders input not found in response")


async def test_include_subfolders_false_limits_inventory_end_to_end(tmp_path, monkeypatch):
    """POST /scan with include_subfolders=false → report contains only top-level files."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))

    (tmp_path / "scan").mkdir()
    (tmp_path / "scan" / "top.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (tmp_path / "scan" / "sub").mkdir()
    (tmp_path / "scan" / "sub" / "nested.sh").write_text("#!/bin/sh\n", encoding="utf-8")

    class _Keys:
        def get_password(self, *args):
            return "KEY"

    class _StubEngine:
        info = EngineInfo(id="virustotal", display_name="VirusTotal", default_per_minute=4)

        async def get_file_report(self, sha256: str):
            return None  # NOT_FOUND

        def metrics_snapshot(self):
            return RequestMetrics.zero()

        async def close(self):
            pass

    app = create_app(
        keyring_module=_Keys(),
        engine_factory=lambda engine_id, api_key: _StubEngine(),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/scan",
            data={
                "folder": str(tmp_path / "scan"),
                "engine": "virustotal",
                "include_subfolders": "false",
            },
        )
        assert response.status_code == 200
        job_id = re.search(r'data-job-id="([^"]+)"', response.text).group(1)
        job = app.state.job_manager.get(job_id)
        await job.task
        assert job.report_id is not None
        report = await client.get(f"/reports/{job.report_id}")
        assert report.status_code == 200
        assert "top.sh" in report.text
        assert "nested.sh" not in report.text
