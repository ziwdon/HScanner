# tests/test_store.py
from pathlib import Path

from hscanner.store import (
    GLOBAL_SCHEMA_VERSION,
    SCAN_SCHEMA_VERSION,
    global_store_path,
    open_global_store,
    open_scan_store,
)


def test_global_store_path_uses_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    assert global_store_path() == tmp_path / "hscanner" / "store.db"


def test_global_store_path_falls_back_to_home_local_state(monkeypatch):
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    assert global_store_path() == Path.home() / ".local" / "state" / "hscanner" / "store.db"


def test_open_global_store_creates_schema_and_version(tmp_path):
    conn = open_global_store(base_dir=tmp_path)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"engine_cache", "quota_counter", "schema_meta"} <= tables
    version = conn.execute("SELECT version FROM schema_meta").fetchone()[0]
    assert version == GLOBAL_SCHEMA_VERSION
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_open_scan_store_creates_schema_under_dot_hscanner(tmp_path):
    conn = open_scan_store(tmp_path)
    assert (tmp_path / ".hscanner" / "scan.db").exists()
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"scan", "file_state", "schema_meta"} <= tables
    assert conn.execute("SELECT version FROM schema_meta").fetchone()[0] == SCAN_SCHEMA_VERSION


def test_reopening_is_idempotent(tmp_path):
    open_global_store(base_dir=tmp_path).close()
    conn = open_global_store(base_dir=tmp_path)  # must not error or duplicate
    assert conn.execute("SELECT COUNT(*) FROM schema_meta").fetchone()[0] == 1


def test_store_connections_set_busy_timeout(tmp_path):
    global_conn = open_global_store(base_dir=tmp_path / "global")
    scan_conn = open_scan_store(tmp_path / "scan")

    assert global_conn.execute("PRAGMA busy_timeout").fetchone()[0] >= 5000
    assert scan_conn.execute("PRAGMA busy_timeout").fetchone()[0] >= 5000
