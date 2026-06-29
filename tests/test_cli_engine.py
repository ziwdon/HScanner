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


def test_combined_requires_all_keys(monkeypatch, tmp_path):
    monkeypatch.setattr("hscanner.cli.load_saved_api_key", lambda engine_id: None)

    result = runner.invoke(app, ["scan", str(tmp_path), "--engine", "combined"])

    assert result.exit_code == 3
    assert "key" in result.output.lower()


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
