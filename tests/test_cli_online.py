# tests/test_cli_online.py
from typer.testing import CliRunner

from hscanner import cli
from hscanner.budget import QuotaStopReason
from hscanner.models import ScanStatus

runner = CliRunner()


def test_no_key_runs_local_only(tmp_path, monkeypatch):
    (tmp_path / "a.sh").write_text("#!/bin/sh\n")
    monkeypatch.delenv("HS_API_KEY_VIRUSTOTAL", raising=False)
    monkeypatch.setattr(cli, "load_saved_api_key", lambda engine_id: None)
    called = {"online": False}

    async def fake_online(*a, **k):
        called["online"] = True
        raise AssertionError("should not run online without a key")

    monkeypatch.setattr(cli, "run_online_scan", fake_online)
    result = runner.invoke(cli.app, ["scan", str(tmp_path)])
    assert result.exit_code in (0, 1, 2)  # a normal local-scan exit code
    assert called["online"] is False


def test_with_key_runs_online_and_maps_quota_exit_code(tmp_path, monkeypatch):
    (tmp_path / "a.sh").write_text("#!/bin/sh\n")
    monkeypatch.setenv("HS_API_KEY_VIRUSTOTAL", "k")
    from hscanner.scanner import OnlineScanOutcome

    async def fake_online(root, engine, upload_consent, **kwargs):
        return OnlineScanOutcome(
            results=[],
            status=ScanStatus.QUOTA_EXHAUSTED,
            quota_stop_reasons=(QuotaStopReason.DAILY,),
        )

    monkeypatch.setattr(cli, "run_online_scan", fake_online)
    monkeypatch.setattr(cli, "_build_engine_client", lambda *a, **kw: _FakeClient())

    result = runner.invoke(cli.app, ["scan", str(tmp_path)])
    assert result.exit_code == 5


class _FakeClient:
    async def close(self):
        pass
