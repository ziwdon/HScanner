from typer.testing import CliRunner

from hscanner.cli import app

runner = CliRunner()


def test_help_lists_bypass_flag():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--bypass-low-risk" in result.output
    assert "--no-bypass-low-risk" in result.output
