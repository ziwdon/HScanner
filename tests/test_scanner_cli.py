import json

from typer.testing import CliRunner

from hscanner.cli import app
from hscanner.errors import ErrorCode
from hscanner.models import ReportCategory
from hscanner.scanner import run_local_scan


def test_local_scan_classifies_and_hashes_hashable_files(tmp_path) -> None:
    (tmp_path / ".env").write_text("SECRET=1", encoding="utf-8")
    (tmp_path / "tool.sh").write_text("#!/bin/sh\n", encoding="utf-8")

    report = run_local_scan(tmp_path)

    by_path = {item.record.relative_path: item for item in report}
    assert by_path[".env"].sha256 is None
    assert by_path["tool.sh"].sha256 is not None


def test_cli_json_flag_emits_valid_json(tmp_path) -> None:
    tool = tmp_path / "tool.sh"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    tool.chmod(0o755)

    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(tmp_path), "--json"])

    parsed = json.loads(result.stdout)
    assert parsed["schema_version"] == 3
    assert "files" in parsed
    relative_paths = [f["relative_path"] for f in parsed["files"]]
    assert "tool.sh" in relative_paths


def test_cli_default_output_is_tab_separated(tmp_path) -> None:
    tool = tmp_path / "tool.sh"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    tool.chmod(0o755)

    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(tmp_path)])

    # Default output should be tab-separated text, not JSON
    assert "\t" in result.stdout


def test_local_scan_hash_permission_error_recorded_not_raised(
    tmp_path, monkeypatch
) -> None:
    # Fix #1: a PermissionError during hashing should populate errors, not abort the scan.
    tool = tmp_path / "tool.sh"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    tool.chmod(0o755)

    def _raise(_path):
        raise PermissionError("denied")

    monkeypatch.setattr("hscanner.scanner.sha256_file", _raise)

    report = run_local_scan(tmp_path)

    by_path = {item.record.relative_path: item for item in report}
    file_result = by_path["tool.sh"]
    assert file_result.sha256 is None
    assert ErrorCode.PERMISSION_DENIED in file_result.errors
    assert file_result.report_category == ReportCategory.ERRORS
