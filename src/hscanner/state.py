from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4


def new_scan_id() -> str:
    return f"scan_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}_{uuid4().hex[:8]}"


def file_state_key(relative_path: str, size: int, mtime_ns: int, sha256: str | None) -> str:
    return f"{relative_path}|{size}|{mtime_ns}|{sha256 or '-'}"


def default_state_dir(root: Path) -> Path:
    return root / ".hscanner"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class ScanState:
    def __init__(self, conn: sqlite3.Connection, root: Path) -> None:
        self.conn = conn
        self.root = str(root)
        self.scan_id: str | None = None
        self.baseline_scan_id: str | None = None

    def start_or_resume(self, *, resume: bool) -> tuple[str, bool]:
        if resume:
            row = self.conn.execute(
                "SELECT scan_id FROM scan WHERE root=? AND status IN ('running', 'interrupted') "
                "ORDER BY started_at DESC LIMIT 1",
                (self.root,),
            ).fetchone()
            if row is not None:
                self.scan_id = row["scan_id"]
                self.baseline_scan_id = row["scan_id"]
                return self.scan_id, True
        row = self.conn.execute(
            "SELECT scan_id FROM scan WHERE root=? AND status='done' "
            "ORDER BY finished_at DESC, started_at DESC LIMIT 1",
            (self.root,),
        ).fetchone()
        self.baseline_scan_id = row["scan_id"] if row is not None else None
        self.scan_id = new_scan_id()
        self.conn.execute(
            "INSERT INTO scan (scan_id, root, started_at, status) VALUES (?, ?, ?, 'running')",
            (self.scan_id, self.root, _now_iso()),
        )
        self.conn.commit()
        return self.scan_id, False

    def _lookup_scan_ids(self) -> tuple[str, ...]:
        ids = []
        if self.scan_id is not None:
            ids.append(self.scan_id)
        if self.baseline_scan_id is not None and self.baseline_scan_id not in ids:
            ids.append(self.baseline_scan_id)
        return tuple(ids)

    def cached_sha256(self, rel_path: str, size: int, mtime_ns: int) -> str | None:
        for scan_id in self._lookup_scan_ids():
            row = self.conn.execute(
                "SELECT sha256 FROM file_state WHERE scan_id=? AND rel_path=? AND size=? "
                "AND mtime_ns=? AND sha256 IS NOT NULL",
                (scan_id, rel_path, size, mtime_ns),
            ).fetchone()
            if row:
                return row["sha256"]
        return None

    def cached_online_state(
        self,
        rel_path: str,
        size: int,
        mtime_ns: int,
        sha256: str,
    ) -> dict[str, str] | None:
        for scan_id in self._lookup_scan_ids():
            row = self.conn.execute(
                "SELECT engine_id, engine_state, lookup_status, upload_status, action "
                "FROM file_state WHERE scan_id=? AND rel_path=? AND size=? AND mtime_ns=? "
                "AND sha256=? AND stage='checked'",
                (scan_id, rel_path, size, mtime_ns, sha256),
            ).fetchone()
            if row is not None:
                return dict(row)
        return None

    def record_online_state(
        self,
        rel_path: str,
        size: int,
        mtime_ns: int,
        sha256: str,
        engine_id: str | None,
        engine_state: str,
        lookup_status: str,
        upload_status: str,
        action: str,
    ) -> None:
        self.conn.execute(
            "UPDATE file_state SET stage='checked', engine_id=?, engine_state=?, "
            "lookup_status=?, upload_status=?, action=?, updated_at=? "
            "WHERE scan_id=? AND rel_path=? AND size=? AND mtime_ns=? AND sha256=?",
            (
                engine_id,
                engine_state,
                lookup_status,
                upload_status,
                action,
                _now_iso(),
                self.scan_id,
                rel_path,
                size,
                mtime_ns,
                sha256,
            ),
        )
        self.conn.commit()

    def record_file(
        self,
        rel_path: str,
        size: int,
        mtime_ns: int,
        sha256: str | None,
        inode: str | None,
        stage: str,
    ) -> None:
        self.conn.execute(
            "INSERT INTO file_state "
            "(scan_id, rel_path, size, mtime_ns, sha256, inode, stage, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(scan_id, rel_path) DO UPDATE SET "
            "size=excluded.size, mtime_ns=excluded.mtime_ns, sha256=excluded.sha256, "
            "inode=excluded.inode, "
            "stage=CASE "
            "WHEN file_state.stage='checked' "
            "AND file_state.size=excluded.size "
            "AND file_state.mtime_ns=excluded.mtime_ns "
            "AND file_state.sha256=excluded.sha256 "
            "THEN file_state.stage ELSE excluded.stage END, "
            "updated_at=excluded.updated_at",
            (self.scan_id, rel_path, size, mtime_ns, sha256, inode, stage, _now_iso()),
        )
        self.conn.commit()

    def _finish(self, status: str) -> None:
        self.conn.execute(
            "UPDATE scan SET status=?, finished_at=? WHERE scan_id=?",
            (status, _now_iso(), self.scan_id),
        )
        self.conn.commit()

    def mark_done(self) -> None:
        self._finish("done")

    def mark_interrupted(self) -> None:
        self._finish("interrupted")
