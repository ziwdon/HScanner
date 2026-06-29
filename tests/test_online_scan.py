from datetime import UTC, datetime

from hscanner.budget import BudgetExhausted, QuotaStopReason, RequestMetrics
from hscanner.cache import EngineCache
from hscanner.engines.base import EngineFileReport, EngineInfo
from hscanner.errors import ErrorCode, HScannerError
from hscanner.models import EngineState, ReportAction, ReportCategory, ScanStatus
from hscanner.scanner import run_online_scan, single_engine_rotation
from hscanner.store import open_global_store

CLEAN = {
    "data": {
        "attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 70}},
        "links": {"self": "https://www.virustotal.com/gui/file/x"},
    }
}


def _report(payload=CLEAN, sha256="sha"):
    attributes = payload["data"]["attributes"]
    return EngineFileReport(
        engine_stats=dict(attributes.get("last_analysis_stats", {})),
        assessment_complete=isinstance(attributes.get("last_analysis_stats"), dict),
        permalink=f"https://www.virustotal.com/gui/file/{sha256}",
        raw=payload,
    )


class FakeVTClient:
    info = EngineInfo(id="virustotal", display_name="VirusTotal", default_per_minute=4)

    def __init__(self, report=None, found=False) -> None:
        self.report = (
            report
            if isinstance(report, EngineFileReport) or report is None
            else _report(report)
        )
        self.found = found
        self.lookups: list[str] = []
        self.uploads: list[str] = []
        self.analyses: list[str] = []

    async def get_file_report(self, sha256: str):
        self.lookups.append(sha256)
        return self.report if self.found else None

    async def upload_file(self, path):
        self.uploads.append(path.name)
        return "analysis-1"

    async def wait_for_analysis(self, analysis_id: str, sha256: str):
        self.analyses.append(analysis_id)
        return _report(sha256=sha256)

    def metrics_snapshot(self):
        return RequestMetrics.zero()


def _write(tmp_path, name: str, content: str):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    p.chmod(0o755)
    return p


def _isolated_cache(tmp_path):
    return EngineCache(open_global_store(base_dir=tmp_path / "cache"), ttl_days=7)


async def test_uploads_unknown_candidate_then_polls_for_verdict(tmp_path) -> None:
    scan_root = tmp_path / "root"
    scan_root.mkdir()
    _write(scan_root, "tool.sh", "#!/bin/sh\n")
    vt = FakeVTClient()

    results = (
        await run_online_scan(
            scan_root, single_engine_rotation(vt),
            upload_consent=True, cache=_isolated_cache(tmp_path),
        )
    ).results

    by_path = {r.record.relative_path: r for r in results}
    assert vt.uploads == ["tool.sh"]
    assert vt.analyses == ["analysis-1"]
    assert by_path["tool.sh"].engine_state == EngineState.UPLOADED
    assert by_path["tool.sh"].report_category == ReportCategory.NO_DETECTIONS


async def test_does_not_upload_without_consent(tmp_path) -> None:
    scan_root = tmp_path / "root"
    scan_root.mkdir()
    _write(scan_root, "tool.sh", "#!/bin/sh\n")
    vt = FakeVTClient()

    results = (
        await run_online_scan(
            scan_root, single_engine_rotation(vt),
            upload_consent=False, cache=_isolated_cache(tmp_path),
        )
    ).results

    by_path = {r.record.relative_path: r for r in results}
    assert vt.uploads == []
    assert by_path["tool.sh"].report_category == ReportCategory.UNKNOWN_BUT_SUSPICIOUS


async def test_identical_files_are_deduped(tmp_path) -> None:
    scan_root = tmp_path / "root"
    scan_root.mkdir()
    _write(scan_root, "a.sh", "#!/bin/sh\nsame\n")
    _write(scan_root, "b.sh", "#!/bin/sh\nsame\n")  # identical content -> same sha256
    vt = FakeVTClient(report=CLEAN, found=True)

    results = (
        await run_online_scan(
            scan_root, single_engine_rotation(vt),
            upload_consent=False, cache=_isolated_cache(tmp_path),
        )
    ).results

    assert len(vt.lookups) == 1  # one lookup served both files
    for r in results:
        assert r.engine_state == EngineState.FOUND
        assert r.engine_id == "virustotal"
    actions = sorted(result.action for result in results)
    assert ReportAction.LOOKUP_FOUND in actions
    assert ReportAction.RESULT_REUSED in actions


async def test_bad_key_stops_vt_work_after_first_failure(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    _write(root, "one.sh", "#!/bin/sh\n1\n")
    _write(root, "two.sh", "#!/bin/sh\n2\n")

    class BadKeyClient(FakeVTClient):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        async def get_file_report(self, sha256: str):
            self.calls += 1
            raise HScannerError(ErrorCode.ENGINE_AUTH_FAILED, "bad key")

    client = BadKeyClient()
    outcome = await run_online_scan(
        root,
        single_engine_rotation(client),
        upload_consent=False,
        cache=_isolated_cache(tmp_path),
    )

    assert client.calls == 1
    assert outcome.status == ScanStatus.AUTH_FAILED
    assert sum(ErrorCode.ENGINE_AUTH_FAILED in result.errors for result in outcome.results) == 1
    failed = next(
        result
        for result in outcome.results
        if ErrorCode.ENGINE_AUTH_FAILED in result.errors
    )
    assert failed.engine_id == "virustotal"
    assert sum(result.engine_state == EngineState.NOT_QUERIED for result in outcome.results) == 1


async def test_ceiling_leaves_remaining_files_not_queried(tmp_path) -> None:
    scan_root = tmp_path / "root"
    scan_root.mkdir()
    _write(scan_root, "a.sh", "#!/bin/sh\n1\n")
    _write(scan_root, "b.sh", "#!/bin/sh\n2\n")

    class CeilingClient(FakeVTClient):
        def __init__(self) -> None:
            super().__init__()
            self.n = 0

        async def get_file_report(self, sha256: str):
            self.n += 1
            if self.n > 1:
                raise BudgetExhausted("ceiling")
            return None

    vt = CeilingClient()
    outcome = await run_online_scan(
        scan_root, single_engine_rotation(vt), upload_consent=False, cache=_isolated_cache(tmp_path)
    )

    states = sorted(r.engine_state for r in outcome.results)
    assert EngineState.NOT_QUERIED in states  # the second file was never queried
    for r in outcome.results:
        assert ErrorCode.ENGINE_QUOTA_EXHAUSTED not in r.errors  # ceiling is not an error
    assert outcome.status == ScanStatus.QUOTA_EXHAUSTED
    assert outcome.quota_stop_reasons == (QuotaStopReason.PER_SCAN,)
    assert outcome.request_metrics == RequestMetrics.zero()


async def test_quota_exhausted_stops_scan_and_sets_flag(tmp_path):
    scan_root = tmp_path / "root"
    scan_root.mkdir()
    _write(scan_root, "a.sh", "#!/bin/sh\n1\n")
    _write(scan_root, "b.sh", "#!/bin/sh\n2\n")

    from hscanner.budget import QuotaExhausted

    class QuotaClient(FakeVTClient):
        def __init__(self):
            super().__init__()
            self.n = 0

        async def get_file_report(self, sha256: str):
            self.n += 1
            if self.n > 1:
                raise QuotaExhausted((QuotaStopReason.DAILY,))
            return None

    vt = QuotaClient()
    outcome = await run_online_scan(
        scan_root, single_engine_rotation(vt), upload_consent=False, cache=_isolated_cache(tmp_path)
    )
    assert outcome.status == ScanStatus.QUOTA_EXHAUSTED
    assert outcome.quota_stop_reasons == (QuotaStopReason.DAILY,)
    assert outcome.request_metrics == RequestMetrics.zero()
    states = sorted(r.engine_state for r in outcome.results)
    assert EngineState.NOT_QUERIED in states  # second file never queried


async def test_fresh_cache_hit_skips_client_lookup(tmp_path):
    scan_root = tmp_path / "root"
    scan_root.mkdir()
    _write(scan_root, "x.sh", "#!/bin/sh\nx\n")
    cache = EngineCache(open_global_store(base_dir=tmp_path / "g"), ttl_days=7)
    vt = FakeVTClient(report=CLEAN, found=True)

    first = await run_online_scan(
        scan_root, single_engine_rotation(vt), upload_consent=False, cache=cache)
    assert len(vt.lookups) == 1  # populated the cache
    assert first.results[0].engine_state == EngineState.FOUND
    assert cache.get("virustotal", first.results[0].sha256).report.raw == CLEAN

    vt2 = FakeVTClient(report=CLEAN, found=True)
    second = await run_online_scan(
        scan_root, single_engine_rotation(vt2), upload_consent=False, cache=cache)
    assert vt2.lookups == []  # served entirely from cache
    assert second.results[0].engine_state == EngineState.FOUND
    assert second.results[0].action == ReportAction.CACHE_HIT


async def test_refresh_bypasses_a_fresh_hit(tmp_path):
    scan_root = tmp_path / "root"
    scan_root.mkdir()
    _write(scan_root, "x.sh", "#!/bin/sh\nx\n")
    cache = EngineCache(open_global_store(base_dir=tmp_path / "g"), ttl_days=7)
    vt = FakeVTClient(report=CLEAN, found=True)
    await run_online_scan(
        scan_root, single_engine_rotation(vt), upload_consent=False, cache=cache)

    vt2 = FakeVTClient(report=CLEAN, found=True)
    await run_online_scan(
        scan_root, single_engine_rotation(vt2),
        upload_consent=False, cache=cache, refresh=True)
    assert len(vt2.lookups) == 1  # re-queried despite a fresh cache hit


async def test_engine_report_is_applied_without_parsing_provider_payload(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    _write(root, "tool.sh", "#!/bin/sh\n")
    payload = {
        "data": {
            "attributes": {
                "last_analysis_date": 1_718_886_000,
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 0,
                    "undetected": 69,
                },
                "last_analysis_results": {
                    "Zulu": {"category": "malicious", "result": "Trojan.Z"},
                    "Alpha": {"category": "undetected", "result": None},
                },
            }
        }
    }
    normalized = EngineFileReport(
        engine_stats={"malicious": 1, "suspicious": 0, "undetected": 69},
        detections=[
            {"engine": "Zulu", "category": "malicious", "name": "Trojan.Z"}
        ],
        permalink="https://example.test/report",
        last_analysis_at=1_718_886_000,
        assessment_complete=True,
        raw=payload,
    )
    outcome = await run_online_scan(
        root,
        single_engine_rotation(FakeVTClient(report=normalized, found=True)),
        upload_consent=False,
        cache=_isolated_cache(tmp_path),
    )
    result = outcome.results[0]
    assert result.assessment_complete is True
    assert result.engine_stats == normalized.engine_stats
    assert result.permalink == "https://example.test/report"
    assert result.last_analysis_at == 1_718_886_000
    assert result.raw_result == payload
    assert result.raw_result is not normalized.raw
    assert result.detections == [
        {"engine": "Zulu", "category": "malicious", "name": "Trojan.Z"}
    ]
    assert result.engine_stats is not normalized.engine_stats
    assert result.detections is not normalized.detections


async def test_broken_cache_does_not_abort_scan(tmp_path):
    """A sqlite3.Error from cache.get/put must degrade gracefully; scan must not abort."""
    import sqlite3

    class BrokenCache:
        def get(self, engine_id, sha256, *, include_stale=False):
            raise sqlite3.OperationalError("disk I/O error")

        def put(self, result):
            raise sqlite3.OperationalError("database is locked")

    scan_root = tmp_path / "root"
    scan_root.mkdir()
    _write(scan_root, "one.sh", "#!/bin/sh\n1\n")
    _write(scan_root, "two.sh", "#!/bin/sh\n2\n")

    vt = FakeVTClient(report=CLEAN, found=True)

    # Must NOT raise even though the cache is broken
    outcome = await run_online_scan(
        scan_root, single_engine_rotation(vt), upload_consent=False, cache=BrokenCache()
    )

    # All files must be present in results
    assert len(outcome.results) == 2

    # cache.get raised → treated as miss → client was consulted → FOUND
    from hscanner.models import EngineState
    for r in outcome.results:
        assert r.engine_state == EngineState.FOUND


# --- Sub-project G: combined-engine failover (Task 6) ------------------------

from hscanner.budget import QuotaExhausted  # noqa: E402
from hscanner.engines.rotation import EngineRotation, EngineSlot  # noqa: E402


class FakeEngine:
    def __init__(self, engine_id, *, lookup_report=None, lookup_exc=None):
        self.info = EngineInfo(engine_id, engine_id.title(), 4)
        self.hooks = None
        self.lookup_report = lookup_report
        self.lookup_exc = lookup_exc
        self.lookups = []
        self.uploads = []

    async def get_file_report(self, sha256):
        self.lookups.append(sha256)
        if self.lookup_exc is not None:
            exc, self.lookup_exc = self.lookup_exc, None  # raise once
            raise exc
        return self.lookup_report

    async def upload_file(self, path):
        self.uploads.append(path)
        return "analysis-1"

    async def wait_for_analysis(self, analysis_id, sha256):
        return EngineFileReport(engine_stats={"malicious": 0}, assessment_complete=True)

    def metrics_snapshot(self):
        return RequestMetrics.zero()

    async def close(self):
        return None


def _rotation(*engines, wait_threshold=300.0):
    clock = {"now": 0.0}
    rot = EngineRotation(
        [EngineSlot(e) for e in engines],
        wait_threshold=wait_threshold,
        monotonic=lambda: clock["now"],
        now=lambda: datetime(2026, 6, 23, 12, 0, tzinfo=UTC),
    )
    return rot, clock


def _g_scan_root(tmp_path):
    # Scan content lives in a subdir so the cache DB (a sibling) is never walked.
    root = tmp_path / "scan"
    root.mkdir()
    (root / "f.bin").write_bytes(b"MZ\x00data")
    return root


def _empty_cache(tmp_path):
    # Isolated, empty cache OUTSIDE the scan root so failover/upload behavior is
    # not masked by a cross-test cache hit (these tests reuse identical content).
    return EngineCache(open_global_store(base_dir=tmp_path / "cache"), ttl_days=7)


async def test_lookup_rate_limit_fails_over_to_next_engine(tmp_path):
    root = _g_scan_root(tmp_path)
    a = FakeEngine("virustotal", lookup_exc=HScannerError(
        ErrorCode.ENGINE_RATE_LIMITED, "rl", retry_after=30))
    b = FakeEngine("metadefender", lookup_report=EngineFileReport(
        engine_stats={"malicious": 1}, assessment_complete=True))
    rot, _ = _rotation(a, b)
    outcome = await run_online_scan(
        root, rot, upload_consent=False, cache=_empty_cache(tmp_path))
    served = [r for r in outcome.results if r.sha256]
    assert served and all(
        r.engine_id == "metadefender" for r in served if r.engine_state.value == "found"
    )


async def test_both_daily_exhausted_stops_quota_exhausted(tmp_path):
    root = _g_scan_root(tmp_path)

    class QuotaEngine(FakeEngine):
        async def get_file_report(self, sha256):
            raise QuotaExhausted((QuotaStopReason.DAILY,))

    a = QuotaEngine("virustotal")
    b = QuotaEngine("metadefender")
    rot, _ = _rotation(a, b, wait_threshold=300.0)
    outcome = await run_online_scan(
        root, rot, upload_consent=False, cache=_empty_cache(tmp_path))
    assert outcome.status == ScanStatus.QUOTA_EXHAUSTED


async def test_both_monthly_exhausted_records_monthly_stop_reason(tmp_path):
    root = _g_scan_root(tmp_path)

    class QuotaEngine(FakeEngine):
        async def get_file_report(self, sha256):
            raise QuotaExhausted((QuotaStopReason.MONTHLY,))

    rotation, _ = _rotation(
        QuotaEngine("virustotal"),
        QuotaEngine("metadefender"),
        wait_threshold=300.0,
    )

    outcome = await run_online_scan(
        root, rotation, upload_consent=False, cache=_empty_cache(tmp_path)
    )

    assert outcome.quota_stop_reasons == (QuotaStopReason.MONTHLY,)


async def test_budget_exhausted_on_a_fails_over_to_b(tmp_path):
    root = _g_scan_root(tmp_path)

    class BudgetEngine(FakeEngine):
        async def get_file_report(self, sha256):
            raise BudgetExhausted("ceiling")

    a = BudgetEngine("virustotal")
    b = FakeEngine("metadefender", lookup_report=EngineFileReport(
        engine_stats={"malicious": 0}, assessment_complete=True))
    rot, _ = _rotation(a, b)
    outcome = await run_online_scan(
        root, rot, upload_consent=False, cache=_empty_cache(tmp_path))
    assert outcome.status == ScanStatus.COMPLETED
    assert any(r.engine_id == "metadefender" for r in outcome.results if r.sha256)


async def test_cross_engine_cache_hit_avoids_live_call(tmp_path):
    from datetime import UTC, datetime

    from hscanner.cache import CachedEngineResult
    from hscanner.hash import sha256_file

    root = _g_scan_root(tmp_path)
    cache = _empty_cache(tmp_path)
    a = FakeEngine("virustotal")  # active, but no report
    b = FakeEngine("metadefender")
    rot, _ = _rotation(a, b)
    sha = sha256_file(root / "f.bin")
    cache.put(CachedEngineResult(
        engine_id="metadefender", sha256=sha, fetched_at=datetime.now(UTC),
        last_analysis_at=None,
        report=EngineFileReport(engine_stats={"malicious": 0}, assessment_complete=True)))
    outcome = await run_online_scan(root, rot, upload_consent=False, cache=cache)
    assert a.lookups == []  # no live call on active engine
    assert any(r.engine_id == "metadefender" for r in outcome.results if r.sha256)


async def test_upload_pin_does_not_reupload_to_other_engine(tmp_path):
    root = _g_scan_root(tmp_path)

    class PollFailEngine(FakeEngine):
        async def get_file_report(self, sha256):
            return None  # not found -> triggers upload

        async def wait_for_analysis(self, analysis_id, sha256):
            raise HScannerError(ErrorCode.ENGINE_RATE_LIMITED, "rl during poll")

    a = PollFailEngine("virustotal")
    b = FakeEngine("metadefender")
    rot, _ = _rotation(a, b)
    await run_online_scan(root, rot, upload_consent=True, cache=_empty_cache(tmp_path))
    assert a.uploads and not b.uploads  # not re-uploaded to B
