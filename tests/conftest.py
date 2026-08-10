# tests/conftest.py
import pytest


@pytest.fixture(autouse=True)
def _isolate_xdg_state_home(tmp_path, monkeypatch):
    """Point XDG_STATE_HOME at a per-test tmp dir.

    The default stores (reports.db, store.db) resolve under $XDG_STATE_HOME
    at call time; without isolation the suite writes junk reports and quota
    counters into the real ~/.local/state/hscanner/. Tests that set the env
    var themselves still win (their monkeypatch.setenv applies after this
    fixture's).
    """
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
