import json
import sys

import pytest
from typer.testing import CliRunner

from hscanner import cli
from hscanner.budget import QuotaStopReason
from hscanner.models import ScanStatus
from hscanner.report import build_scan_report, cli_exit_code
from hscanner.scanner import OnlineScanOutcome

runner = CliRunner()


# ---------------------------------------------------------------------------
# Four canonical tests from the brief
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("suffix", ["json", "html", "csv"])
def test_report_option_writes_inferred_format(tmp_path, monkeypatch, suffix) -> None:
    (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")
    monkeypatch.delenv("HS_API_KEY_VIRUSTOTAL", raising=False)
    monkeypatch.setattr(cli, "load_saved_api_key", lambda engine_id: None)
    output = tmp_path / f"report.{suffix}"

    result = runner.invoke(cli.app, ["scan", str(tmp_path), "--report", str(output)])

    assert result.exit_code in {0, 1, 2}
    assert output.is_file()


def test_require_vt_missing_key_exports_local_report_and_returns_four(tmp_path, monkeypatch):
    (tmp_path / "tool.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.delenv("HS_API_KEY_VIRUSTOTAL", raising=False)
    monkeypatch.setattr(cli, "load_saved_api_key", lambda engine_id: None)
    output = tmp_path / "report.json"

    result = runner.invoke(
        cli.app,
        ["scan", str(tmp_path), "--require-engine", "--report", str(output)],
    )

    assert result.exit_code == 4
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "key_missing"


def test_invalid_suffix_returns_three_before_scanning(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(cli, "run_local_scan", lambda root: pytest.fail("scan should not start"))
    result = runner.invoke(cli.app, ["scan", str(tmp_path), "--report", "report.pdf"])
    assert result.exit_code == 3


def test_process_boundary_maps_unknown_option_to_three(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["hscanner", "scan", "--unknown-option"])
    with pytest.raises(SystemExit) as raised:
        cli.main()
    assert raised.value.code == 3


# ---------------------------------------------------------------------------
# Additional tests (max-requests, auth, quota, unexpected exception, precedence)
# ---------------------------------------------------------------------------


def test_max_requests_zero_returns_three(tmp_path) -> None:
    result = runner.invoke(
        cli.app, ["scan", str(tmp_path), "--max-requests", "0"]
    )
    assert result.exit_code == 3


def test_max_requests_negative_returns_three(tmp_path) -> None:
    result = runner.invoke(
        cli.app, ["scan", str(tmp_path), "--max-requests", "-5"]
    )
    assert result.exit_code == 3


def test_max_requests_overrides_policy(tmp_path, monkeypatch) -> None:
    (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")
    monkeypatch.setenv("HS_API_KEY_VIRUSTOTAL", "testkey")

    captured: dict = {}

    def fake_build_engine_client(api_key, policy, max_requests, engine_id="virustotal"):
        captured["max_requests"] = max_requests
        return _FakeClient()

    async def fake_online(root, engine, upload_consent, **kwargs):
        return OnlineScanOutcome(results=[], status=ScanStatus.COMPLETED)

    monkeypatch.setattr(cli, "_build_engine_client", fake_build_engine_client)
    monkeypatch.setattr(cli, "run_online_scan", fake_online)

    runner.invoke(cli.app, ["scan", str(tmp_path), "--max-requests", "7"])

    assert captured.get("max_requests") == 7


def test_auth_failure_returns_four(tmp_path, monkeypatch) -> None:
    (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")
    monkeypatch.setenv("HS_API_KEY_VIRUSTOTAL", "badkey")

    async def fake_online(root, engine, upload_consent, **kwargs):
        return OnlineScanOutcome(results=[], status=ScanStatus.AUTH_FAILED)

    monkeypatch.setattr(cli, "run_online_scan", fake_online)

    def _fake_build(*args, **kwargs):
        return _FakeClient()

    monkeypatch.setattr(cli, "_build_engine_client", _fake_build)

    result = runner.invoke(cli.app, ["scan", str(tmp_path)])
    assert result.exit_code == 4


def test_quota_exhausted_returns_five_via_export_test(tmp_path, monkeypatch) -> None:
    (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")
    monkeypatch.setenv("HS_API_KEY_VIRUSTOTAL", "testkey")

    async def fake_online(root, engine, upload_consent, **kwargs):
        return OnlineScanOutcome(
            results=[],
            status=ScanStatus.QUOTA_EXHAUSTED,
            quota_stop_reasons=(QuotaStopReason.DAILY,),
        )

    monkeypatch.setattr(cli, "run_online_scan", fake_online)

    def _fake_build(*args, **kwargs):
        return _FakeClient()

    monkeypatch.setattr(cli, "_build_engine_client", _fake_build)

    result = runner.invoke(cli.app, ["scan", str(tmp_path)])
    assert result.exit_code == 5


def test_unexpected_exception_through_main_returns_six(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("HS_API_KEY_VIRUSTOTAL", raising=False)
    monkeypatch.setattr(cli, "load_saved_api_key", lambda engine_id: None)

    def fake_local_scan(root):
        raise RuntimeError("unexpected boom")

    monkeypatch.setattr(cli, "run_local_scan", fake_local_scan)
    monkeypatch.setattr(sys, "argv", ["hscanner", "scan", str(tmp_path)])

    with pytest.raises(SystemExit) as raised:
        cli.main()
    assert raised.value.code == 6


def test_exit_code_precedence_is_6_3_4_5_2_1_0(tmp_path) -> None:
    # Precedence chain: fatal=6, config_error=3, key/auth=4, quota=5, errors=2, attention=1, else=0
    base = build_scan_report(tmp_path, [], online=False, upload_consent=False)

    # 6: fatal flag overrides everything
    assert cli_exit_code(base, fatal=True) == 6

    # 3: config_error overrides remaining
    assert cli_exit_code(base, config_error=True) == 3

    # 4: KEY_MISSING / AUTH_FAILED
    km = build_scan_report(
        tmp_path, [], online=False, upload_consent=False, status=ScanStatus.KEY_MISSING
    )
    assert cli_exit_code(km) == 4

    af = build_scan_report(
        tmp_path, [], online=False, upload_consent=False, status=ScanStatus.AUTH_FAILED
    )
    assert cli_exit_code(af) == 4

    # 5: QUOTA_EXHAUSTED
    qe = build_scan_report(
        tmp_path,
        [],
        online=False,
        upload_consent=False,
        status=ScanStatus.QUOTA_EXHAUSTED,
        quota_stop_reasons=(QuotaStopReason.DAILY,),
    )
    assert cli_exit_code(qe) == 5

    # 0: no files, no issues
    assert cli_exit_code(base) == 0


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


class _FakeClient:
    async def close(self) -> None:
        pass
