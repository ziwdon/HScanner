from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from hscanner.budget import RequestMetrics
from hscanner.progress import ScanHooks


@dataclass
class EngineFileReport:
    """Normalized, engine-neutral output from a file assessment.

    ``engine_stats`` uses the report vocabulary ``malicious``, ``suspicious``,
    ``undetected``, ``harmless``, ``timeout``, ``failure``, and
    ``type-unsupported``. Engines populate the values they have. ``detections``
    lists only malicious or suspicious entries.
    """

    engine_stats: dict[str, int] = field(default_factory=dict)
    detections: list[dict[str, str]] = field(default_factory=list)
    permalink: str | None = None
    last_analysis_at: int | None = None
    assessment_complete: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    def to_json_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json_dict(cls, data: dict[str, Any]) -> "EngineFileReport":
        return cls(
            engine_stats={
                str(key): int(value) for key, value in (data.get("engine_stats") or {}).items()
            },
            detections=[dict(detection) for detection in (data.get("detections") or [])],
            permalink=data.get("permalink"),
            last_analysis_at=data.get("last_analysis_at"),
            assessment_complete=bool(data.get("assessment_complete")),
            raw=dict(data.get("raw") or {}),
        )


@dataclass(frozen=True)
class EngineInfo:
    id: str
    display_name: str
    default_per_minute: int


@runtime_checkable
class ScanEngine(Protocol):
    info: EngineInfo
    hooks: ScanHooks | None

    async def get_file_report(self, sha256: str) -> EngineFileReport | None: ...

    async def upload_file(self, path: Path) -> str: ...

    async def wait_for_analysis(self, analysis_id: str, sha256: str) -> EngineFileReport: ...

    def metrics_snapshot(self) -> RequestMetrics: ...

    async def close(self) -> None: ...
