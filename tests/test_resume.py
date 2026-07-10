from hscanner import scanner
from hscanner.cache import EngineCache
from hscanner.engines.base import EngineInfo
from hscanner.models import EngineState, LookupStatus, ReportAction, ScanStatus
from hscanner.progress import EventType, ScanController
from hscanner.scanner import run_local_scan, run_online_scan, single_engine_rotation
from hscanner.state import ScanState
from hscanner.store import open_global_store, open_scan_store


def test_resume_skips_rehash_of_unchanged_file(tmp_path, monkeypatch):
    f = tmp_path / "doc.bin"
    f.write_bytes(b"stable-content")

    st = ScanState(open_scan_store(tmp_path), tmp_path)
    st.start_or_resume(resume=False)
    run_local_scan(tmp_path, scan_state=st)  # first pass records the hash

    calls: list[str] = []
    real = scanner.sha256_file
    monkeypatch.setattr(
        scanner, "sha256_file", lambda p, *a, **k: (calls.append(p.name), real(p, *a, **k))[1]
    )

    st2 = ScanState(open_scan_store(tmp_path), tmp_path)
    resumed_id, resuming = st2.start_or_resume(resume=True)
    assert resuming is True
    results = run_local_scan(tmp_path, scan_state=st2)
    assert calls == []  # unchanged file not re-hashed on resume
    assert results[0].sha256 is not None


def test_changed_file_is_rehashed_on_resume(tmp_path, monkeypatch):
    f = tmp_path / "doc.bin"
    f.write_bytes(b"v1")
    st = ScanState(open_scan_store(tmp_path), tmp_path)
    st.start_or_resume(resume=False)
    run_local_scan(tmp_path, scan_state=st)

    f.write_bytes(b"v2-different-size")  # size + mtime change

    calls: list[str] = []
    real = scanner.sha256_file
    monkeypatch.setattr(
        scanner, "sha256_file", lambda p, *a, **k: (calls.append(p.name), real(p, *a, **k))[1]
    )
    st2 = ScanState(open_scan_store(tmp_path), tmp_path)
    st2.start_or_resume(resume=True)
    run_local_scan(tmp_path, scan_state=st2)
    assert calls == ["doc.bin"]  # changed file re-hashed


class NotFoundClient:
    info = EngineInfo(id="virustotal", display_name="VirusTotal", default_per_minute=1000)

    def __init__(self) -> None:
        self.lookups: list[str] = []

    async def get_file_report(self, sha256: str):
        self.lookups.append(sha256)
        return None

    async def close(self) -> None:
        return None

    def metrics_snapshot(self):
        from hscanner.budget import RequestMetrics

        return RequestMetrics.zero()


async def test_repeat_scan_reuses_persisted_not_found_online_outcome(tmp_path):
    tool = tmp_path / "tool.sh"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    tool.chmod(0o755)
    cache = EngineCache(open_global_store(base_dir=tmp_path.parent / f"{tmp_path.name}-cache"))

    first_state = ScanState(open_scan_store(tmp_path), tmp_path)
    first_state.start_or_resume(resume=False)
    first_client = NotFoundClient()
    first = await run_online_scan(
        tmp_path,
        single_engine_rotation(first_client),
        upload_consent=False,
        cache=cache,
        scan_state=first_state,
    )
    assert first_client.lookups
    assert first.results[0].engine_state == EngineState.NOT_FOUND

    second_state = ScanState(open_scan_store(tmp_path), tmp_path)
    second_state.start_or_resume(resume=False)
    second_client = NotFoundClient()
    second = await run_online_scan(
        tmp_path,
        single_engine_rotation(second_client),
        upload_consent=False,
        cache=cache,
        scan_state=second_state,
    )

    assert second_client.lookups == []
    assert second.results[0].engine_state == EngineState.NOT_FOUND
    assert second.results[0].lookup_status == LookupStatus.NOT_FOUND
    assert second.results[0].action == ReportAction.RESULT_REUSED


async def test_refresh_ignores_persisted_not_found_online_outcome(tmp_path):
    tool = tmp_path / "tool.sh"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    tool.chmod(0o755)
    cache = EngineCache(open_global_store(base_dir=tmp_path.parent / f"{tmp_path.name}-cache"))

    first_state = ScanState(open_scan_store(tmp_path), tmp_path)
    first_state.start_or_resume(resume=False)
    await run_online_scan(
        tmp_path,
        single_engine_rotation(NotFoundClient()),
        upload_consent=False,
        cache=cache,
        scan_state=first_state,
    )

    second_state = ScanState(open_scan_store(tmp_path), tmp_path)
    second_state.start_or_resume(resume=False)
    second_client = NotFoundClient()
    await run_online_scan(
        tmp_path,
        single_engine_rotation(second_client),
        upload_consent=False,
        cache=cache,
        scan_state=second_state,
        refresh=True,
    )

    assert second_client.lookups


async def test_interrupted_resume_reuses_processed_online_outcomes(tmp_path):
    for name in ("a.sh", "b.sh", "c.sh"):
        tool = tmp_path / name
        tool.write_text(f"#!/bin/sh\necho {name}\n", encoding="utf-8")
        tool.chmod(0o755)
    cache = EngineCache(open_global_store(base_dir=tmp_path.parent / f"{tmp_path.name}-cache"))
    controller = ScanController()
    finished = 0

    def cancel_after_first_file(event) -> None:
        nonlocal finished
        if event.type == EventType.FILE_FINISHED:
            finished += 1
            if finished == 1:
                controller.cancel()

    first_state = ScanState(open_scan_store(tmp_path), tmp_path)
    first_state.start_or_resume(resume=False)
    first_client = NotFoundClient()
    first = await run_online_scan(
        tmp_path,
        single_engine_rotation(first_client),
        upload_consent=False,
        cache=cache,
        scan_state=first_state,
        observer=cancel_after_first_file,
        controller=controller,
    )
    assert first.status == ScanStatus.CANCELLED
    assert len(first_client.lookups) == 1

    second_state = ScanState(open_scan_store(tmp_path), tmp_path)
    _, resuming = second_state.start_or_resume(resume=True)
    assert resuming is True
    second_client = NotFoundClient()
    second = await run_online_scan(
        tmp_path,
        single_engine_rotation(second_client),
        upload_consent=False,
        cache=cache,
        scan_state=second_state,
    )

    assert second.status == ScanStatus.COMPLETED
    assert len(second_client.lookups) == 2
    reused = [result for result in second.results if result.action == ReportAction.RESULT_REUSED]
    assert len(reused) == 1
    assert reused[0].lookup_status == LookupStatus.NOT_FOUND
