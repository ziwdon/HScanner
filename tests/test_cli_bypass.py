import typer

from hscanner.cli import app


def _scan_option_names() -> set[str]:
    """Return all option flag strings for the scan command (rendering-independent)."""
    group = typer.main.get_command(app)
    cmd = group.commands["scan"]
    names: set[str] = set()
    for p in cmd.params:
        if hasattr(p, "opts"):
            names.update(p.opts)
            names.update(getattr(p, "secondary_opts", []))
    return names


def test_help_lists_bypass_flag():
    names = _scan_option_names()
    assert "--bypass-low-risk" in names
    assert "--no-bypass-low-risk" in names


def test_help_lists_include_subfolders_flag():
    names = _scan_option_names()
    assert "--include-subfolders" in names
    assert "--no-include-subfolders" in names
