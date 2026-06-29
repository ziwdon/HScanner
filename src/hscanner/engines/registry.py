from typing import Any

from hscanner.budget import RequestBudget
from hscanner.engines.base import EngineInfo, ScanEngine
from hscanner.engines.metadefender import MetaDefenderEngine
from hscanner.engines.rotation import EngineRotation, EngineSlot
from hscanner.engines.virustotal import VirusTotalEngine

ENGINES: dict[str, EngineInfo] = {
    "virustotal": EngineInfo("virustotal", "VirusTotal", 4),
    "metadefender": EngineInfo("metadefender", "MetaDefender", 10),
}

COMBINED_ENGINE_IDS: list[str] = list(ENGINES)  # fixed priority order


def engine_ids() -> list[str]:
    return list(ENGINES)


def build_engine(
    engine_id: str,
    api_key: str,
    *,
    budget: RequestBudget | None = None,
    poll_timeout: float = 600.0,
    **kwargs: Any,
) -> ScanEngine:
    if engine_id == "virustotal":
        return VirusTotalEngine(
            api_key,
            budget=budget,
            poll_timeout=poll_timeout,
            **kwargs,
        )
    if engine_id == "metadefender":
        return MetaDefenderEngine(
            api_key,
            budget=budget,
            poll_timeout=poll_timeout,
            **kwargs,
        )
    raise ValueError(f"Unknown engine: {engine_id}")


def build_rotation(
    engine_ids: list[str],
    engines: list[ScanEngine],
    *,
    wait_threshold: float = 300.0,
) -> EngineRotation:
    if len(engine_ids) != len(engines):
        raise ValueError("engine_ids and engines must be parallel lists")
    slots = [EngineSlot(engine) for engine in engines]
    return EngineRotation(slots, wait_threshold=wait_threshold)
