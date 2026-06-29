import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from hscanner.engines.base import EngineFileReport


@dataclass
class CachedEngineResult:
    engine_id: str
    sha256: str
    fetched_at: datetime
    last_analysis_at: int | None
    report: EngineFileReport

    def is_fresh(self, ttl_days: int) -> bool:
        return datetime.now(UTC) - self.fetched_at <= timedelta(days=ttl_days)


class EngineCache:
    def __init__(self, conn: sqlite3.Connection, ttl_days: int = 7) -> None:
        self.conn = conn
        self.ttl_days = ttl_days

    def get(
        self, engine_id: str, sha256: str, *, include_stale: bool = False
    ) -> "CachedEngineResult | None":
        row = self.conn.execute(
            "SELECT engine_id, sha256, fetched_at, last_analysis_at, payload "
            "FROM engine_cache WHERE engine_id=? AND sha256=?",
            (engine_id, sha256),
        ).fetchone()
        if row is None:
            return None
        result = CachedEngineResult(
            engine_id=row["engine_id"],
            sha256=row["sha256"],
            fetched_at=datetime.fromisoformat(row["fetched_at"]),
            last_analysis_at=row["last_analysis_at"],
            report=EngineFileReport.from_json_dict(json.loads(row["payload"])),
        )
        if include_stale or result.is_fresh(self.ttl_days):
            return result
        return None

    def put(self, result: "CachedEngineResult") -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO engine_cache "
            "(engine_id, sha256, fetched_at, last_analysis_at, payload) VALUES (?, ?, ?, ?, ?)",
            (
                result.engine_id,
                result.sha256,
                result.fetched_at.astimezone(UTC).isoformat(),
                result.last_analysis_at,
                json.dumps(result.report.to_json_dict()),
            ),
        )
        self.conn.commit()
