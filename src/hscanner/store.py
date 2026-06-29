# src/hscanner/store.py
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

GLOBAL_SCHEMA_VERSION = 2
SCAN_SCHEMA_VERSION = 1

_GLOBAL_DDL = """
CREATE TABLE IF NOT EXISTS engine_cache (
    engine_id          TEXT NOT NULL,
    sha256             TEXT NOT NULL,
    fetched_at         TEXT NOT NULL,
    last_analysis_at   INTEGER,
    payload            TEXT NOT NULL,
    PRIMARY KEY (engine_id, sha256)
);
CREATE TABLE IF NOT EXISTS quota_counter (
    period_key TEXT PRIMARY KEY,
    count      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS schema_meta (version INTEGER NOT NULL);
"""

_SCAN_DDL = """
CREATE TABLE IF NOT EXISTS scan (
    scan_id     TEXT PRIMARY KEY,
    root        TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS file_state (
    scan_id    TEXT NOT NULL,
    rel_path   TEXT NOT NULL,
    size       INTEGER NOT NULL,
    mtime_ns   INTEGER NOT NULL,
    sha256     TEXT,
    inode      TEXT,
    stage      TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (scan_id, rel_path)
);
CREATE TABLE IF NOT EXISTS schema_meta (version INTEGER NOT NULL);
"""


def global_store_path(base_dir: Path | None = None) -> Path:
    if base_dir is None:
        xdg = os.environ.get("XDG_STATE_HOME")
        base_dir = Path(xdg) if xdg else Path.home() / ".local" / "state"
    return base_dir / "hscanner" / "store.db"


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init_schema(conn: sqlite3.Connection, ddl: str, version: int) -> None:
    conn.executescript(ddl)
    if conn.execute("SELECT COUNT(*) FROM schema_meta").fetchone()[0] == 0:
        conn.execute("INSERT INTO schema_meta (version) VALUES (?)", (version,))
    conn.commit()


def open_global_store(base_dir: Path | None = None) -> sqlite3.Connection:
    conn = _connect(global_store_path(base_dir))
    _init_schema(conn, _GLOBAL_DDL, GLOBAL_SCHEMA_VERSION)
    return conn


def open_scan_store(root: Path) -> sqlite3.Connection:
    conn = _connect(root / ".hscanner" / "scan.db")
    _init_schema(conn, _SCAN_DDL, SCAN_SCHEMA_VERSION)
    return conn
