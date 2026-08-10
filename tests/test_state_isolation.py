# tests/test_state_isolation.py
import os
from pathlib import Path

from hscanner.store import global_store_path
from hscanner.web.persistent_reports import default_report_store_path


def test_suite_state_dir_is_isolated_from_real_home():
    """The suite must never write to the real ~/.local/state/hscanner.

    Guaranteed by the autouse fixture in tests/conftest.py that points
    XDG_STATE_HOME at a per-test tmp dir. Both default store resolvers read
    the env var at call time, so these assertions prove the fixture is active.
    """
    xdg = os.environ.get("XDG_STATE_HOME")
    assert xdg is not None, "autouse fixture in tests/conftest.py must set XDG_STATE_HOME"
    assert Path(xdg) != Path.home() / ".local" / "state"
    assert default_report_store_path() == Path(xdg) / "hscanner" / "reports.db"
    assert global_store_path() == Path(xdg) / "hscanner" / "store.db"
