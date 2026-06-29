from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from hscanner.report import ScanReport, report_payload, scan_report_from_payload

_DDL = """
CREATE TABLE IF NOT EXISTS reports (
    report_id        TEXT PRIMARY KEY,
    generated_at     TEXT NOT NULL,
    last_accessed_at TEXT NOT NULL,
    payload          TEXT NOT NULL
);
"""


def default_report_store_path(base_dir: Path | None = None) -> Path:
    if base_dir is None:
        xdg = os.environ.get("XDG_STATE_HOME")
        base_dir = Path(xdg) if xdg else Path.home() / ".local" / "state"
    return base_dir / "hscanner" / "reports.db"


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


class PersistentReportStore:
    def __init__(
        self,
        *,
        path: Path | None = None,
        retention_seconds: float = 7 * 24 * 3600,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.path = path or default_report_store_path()
        self.retention_seconds = retention_seconds
        self._now = now
        self._init_schema()

    def put(self, report: ScanReport) -> None:
        payload = json.dumps(report_payload(report), sort_keys=True)
        accessed_at = _utc_text(self._now())
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO reports "
                "(report_id, generated_at, last_accessed_at, payload) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(report_id) DO UPDATE SET "
                "generated_at=excluded.generated_at, "
                "last_accessed_at=excluded.last_accessed_at, "
                "payload=excluded.payload",
                (report.report_id, report.generated_at, accessed_at, payload),
            )
            conn.commit()
        self.delete_expired()

    def get(self, report_id: str) -> ScanReport | None:
        self.delete_expired()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM reports WHERE report_id=?",
                (report_id,),
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                "UPDATE reports SET last_accessed_at=? WHERE report_id=?",
                (_utc_text(self._now()), report_id),
            )
            conn.commit()
        return scan_report_from_payload(json.loads(row["payload"]))

    def list_reports(self) -> list[ScanReport]:
        self.delete_expired()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM reports ORDER BY generated_at DESC, report_id ASC"
            ).fetchall()
        return [scan_report_from_payload(json.loads(row["payload"])) for row in rows]

    def delete_expired(self) -> None:
        cutoff = self._now().astimezone(UTC).timestamp() - self.retention_seconds
        with self._connect() as conn:
            rows = conn.execute("SELECT report_id, last_accessed_at FROM reports").fetchall()
            expired = [
                row["report_id"]
                for row in rows
                if _parse_utc(row["last_accessed_at"]).timestamp() <= cutoff
            ]
            conn.executemany(
                "DELETE FROM reports WHERE report_id=?",
                ((report_id,) for report_id in expired),
            )
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_DDL)
            conn.commit()
