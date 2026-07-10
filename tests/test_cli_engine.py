from typer.testing import CliRunner

from hscanner.cli import app

runner = CliRunner()


def test_invalid_engine_is_rejected(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path), "--engine", "bogus"])
    assert result.exit_code == 3


def test_engine_help_lists_choices():
    result = runner.invoke(app, ["scan", "--help"])
    assert "--engine" in result.output


def test_max_requests_help_documents_combined_per_engine_ceiling():
    result = runner.invoke(app, ["scan", "--help"])

    assert "per-engine" in result.output


def test_combined_without_keys_runs_local_inventory(monkeypatch, tmp_path):
    monkeypatch.setattr("hscanner.cli.load_saved_api_key", lambda engine_id: None)
    (tmp_path / "tool.sh").write_text("#!/bin/sh\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--engine", "combined", "--json"])

    assert result.exit_code == 1
    assert '"online": false' in result.output
    assert "key" in result.output.lower()


def test_combined_without_keys_require_engine_exits_4(monkeypatch, tmp_path):
    monkeypatch.setattr("hscanner.cli.load_saved_api_key", lambda engine_id: None)

    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--engine", "combined", "--require-engine"],
    )

    assert result.exit_code == 4
    assert "key" in result.output.lower()


def test_combined_partial_keys_fall_back_to_local_inventory(monkeypatch, tmp_path):
    def key_for(engine_id):
        return "key" if engine_id == "virustotal" else None

    monkeypatch.setattr("hscanner.cli.load_saved_api_key", key_for)
    (tmp_path / "tool.sh").write_text("#!/bin/sh\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--engine", "combined", "--json"])

    assert result.exit_code == 1
    assert "MetaDefender" in result.output
    assert '"online": false' in result.output


def test_wait_threshold_must_be_positive(tmp_path):
    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--engine",
            "virustotal",
            "--wait-threshold",
            "0",
        ],
    )

    assert result.exit_code == 3
