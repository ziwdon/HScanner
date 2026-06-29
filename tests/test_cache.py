from datetime import UTC, datetime, timedelta

from hscanner.cache import CachedEngineResult, EngineCache
from hscanner.engines.base import EngineFileReport
from hscanner.store import open_global_store

_EID = "virustotal"


def _result(sha="a" * 64, fetched_at=None):
    return CachedEngineResult(
        engine_id=_EID,
        sha256=sha,
        fetched_at=fetched_at or datetime.now(UTC),
        last_analysis_at=123,
        report=EngineFileReport(raw={"data": {"id": sha}}),
    )


def test_miss_returns_none(tmp_path):
    cache = EngineCache(open_global_store(base_dir=tmp_path), ttl_days=7)
    assert cache.get(_EID, "b" * 64) is None


def test_put_then_fresh_get_roundtrips(tmp_path):
    cache = EngineCache(open_global_store(base_dir=tmp_path), ttl_days=7)
    cache.put(_result())
    got = cache.get(_EID, "a" * 64)
    assert got is not None
    assert got.report.raw == {"data": {"id": "a" * 64}}
    assert got.last_analysis_at == 123


def test_stale_entry_is_hidden_unless_include_stale(tmp_path):
    cache = EngineCache(open_global_store(base_dir=tmp_path), ttl_days=7)
    cache.put(_result(fetched_at=datetime.now(UTC) - timedelta(days=8)))
    assert cache.get(_EID, "a" * 64) is None
    assert cache.get(_EID, "a" * 64, include_stale=True) is not None


def test_put_replaces_existing(tmp_path):
    cache = EngineCache(open_global_store(base_dir=tmp_path), ttl_days=7)
    cache.put(_result())
    newer = CachedEngineResult(
        _EID, "a" * 64, datetime.now(UTC), 999, EngineFileReport(raw={"data": {"id": "new"}})
    )
    cache.put(newer)
    assert cache.get(_EID, "a" * 64).last_analysis_at == 999


def test_cache_is_engine_scoped(tmp_path):
    from datetime import UTC, datetime

    from hscanner.cache import CachedEngineResult, EngineCache
    from hscanner.engines.base import EngineFileReport
    from hscanner.store import open_global_store
    conn = open_global_store(tmp_path)
    cache = EngineCache(conn)
    report = EngineFileReport(engine_stats={"malicious": 1})
    cache.put(CachedEngineResult("virustotal", "abc", datetime.now(UTC), None, report))
    assert cache.get("virustotal", "abc") is not None
    assert cache.get("metadefender", "abc") is None  # not shared across engines
