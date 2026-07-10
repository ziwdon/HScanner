import pytest

from hscanner.cache import EngineCache
from hscanner.engines.base import EngineFileReport, EngineInfo
from hscanner.models import (
    EngineState,
    LookupStatus,
    ReportAction,
    ScanOutcome,
    UploadStatus,
)
from hscanner.scanner import SingleFileNotEligible, scan_single_file
from hscanner.store import open_global_store

_FAKE_INFO = EngineInfo(id="virustotal", display_name="VirusTotal", default_per_minute=4)

_REPORT = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70},
                                   "last_analysis_results": {}}}}
_ENGINE_REPORT = EngineFileReport(
    engine_stats={"malicious": 0, "harmless": 70},
    assessment_complete=True,
    raw=_REPORT,
)


class FoundClient:
    info = _FAKE_INFO
    async def get_file_report(self, sha):
        return _ENGINE_REPORT
    async def upload_file(self, path):
        raise AssertionError("should not upload when already found")


class UploadClient:
    info = _FAKE_INFO
    def __init__(self):
        self.uploaded = False
    async def get_file_report(self, sha):
        return None
    async def upload_file(self, path):
        self.uploaded = True
        return "analysis-1"
    async def wait_for_analysis(self, analysis_id, sha):
        return _ENGINE_REPORT


def _cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    return EngineCache(open_global_store())


@pytest.mark.asyncio
async def test_sensitive_file_rejected(tmp_path, monkeypatch):
    (tmp_path / "id_rsa.pem").write_text("secret")
    with pytest.raises(SingleFileNotEligible) as exc:
        await scan_single_file(tmp_path, "id_rsa.pem", FoundClient(),
                               _cache(tmp_path, monkeypatch))
    assert exc.value.reason == "sensitive"


@pytest.mark.asyncio
async def test_low_risk_rejected(tmp_path, monkeypatch):
    (tmp_path / "movie.mp4").write_bytes(b"\x00data")
    with pytest.raises(SingleFileNotEligible) as exc:
        await scan_single_file(tmp_path, "movie.mp4", FoundClient(),
                               _cache(tmp_path, monkeypatch))
    assert exc.value.reason == "not_priority"


@pytest.mark.asyncio
async def test_vanished_file_raises(tmp_path, monkeypatch):
    with pytest.raises(FileNotFoundError):
        await scan_single_file(tmp_path, "ghost.sh", FoundClient(),
                               _cache(tmp_path, monkeypatch))


@pytest.mark.asyncio
async def test_path_escape_raises_clean_single_file_error(tmp_path, monkeypatch):
    (tmp_path / "outside.sh").write_text("#!/bin/sh\n")

    with pytest.raises(SingleFileNotEligible) as exc:
        await scan_single_file(
            tmp_path / "scan",
            "../outside.sh",
            FoundClient(),
            _cache(tmp_path, monkeypatch),
        )

    assert exc.value.reason == "invalid_path"


@pytest.mark.asyncio
async def test_found_on_relookup_does_not_upload(tmp_path, monkeypatch):
    (tmp_path / "tool.sh").write_text("#!/bin/sh\n")
    res = await scan_single_file(tmp_path, "tool.sh", FoundClient(),
                                 _cache(tmp_path, monkeypatch))
    assert res.engine_state == EngineState.FOUND
    assert res.engine_id == "virustotal"
    assert res.lookup_status == LookupStatus.FOUND
    assert res.upload_status == UploadStatus.NOT_UPLOADED
    assert res.outcome == ScanOutcome.NO_DETECTIONS


@pytest.mark.asyncio
async def test_not_found_uploads_and_polls(tmp_path, monkeypatch):
    (tmp_path / "tool.sh").write_text("#!/bin/sh\n")
    client = UploadClient()
    res = await scan_single_file(tmp_path, "tool.sh", client, _cache(tmp_path, monkeypatch))
    assert client.uploaded is True
    assert res.action == ReportAction.ANALYSIS_COMPLETED
    assert res.engine_state == EngineState.UPLOADED
    assert res.engine_id == "virustotal"
    assert res.lookup_status == LookupStatus.NOT_FOUND
    assert res.upload_status == UploadStatus.ANALYSIS_COMPLETE
    assert res.outcome == ScanOutcome.NO_DETECTIONS


@pytest.mark.asyncio
async def test_symlink_is_rejected_and_never_uploaded(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    target = tmp_path / "real.sh"
    target.write_text("#!/bin/sh\n")
    link = tmp_path / "link.sh"
    link.symlink_to(target)

    class _Spy:
        def __init__(self): self.uploaded = False
        async def get_file_report(self, sha): return None
        async def upload_file(self, path):
            self.uploaded = True
            return "x"
        async def wait_for_analysis(self, a, s): return EngineFileReport()

    spy = _Spy()
    with pytest.raises(SingleFileNotEligible):
        await scan_single_file(tmp_path, "link.sh", spy, EngineCache(open_global_store()))
    assert spy.uploaded is False
