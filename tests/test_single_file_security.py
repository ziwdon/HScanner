# tests/test_single_file_security.py
"""Security regression tests for the on-demand per-file scan path.

Guard: a sensitive file (classified as SKIPPED) must NEVER be uploaded via
scan_single_file, regardless of what the caller requests.  The function raises
SingleFileNotEligible("sensitive") before any engine method is called.

This guarantee is tested for *every* engine shape (VirusTotal and MetaDefender)
so that adding a new engine cannot silently break the invariant.
"""

import pytest

from hscanner.cache import EngineCache
from hscanner.engines.base import EngineFileReport, EngineInfo
from hscanner.models import OutcomeReason, ScanOutcome
from hscanner.scanner import SingleFileNotEligible, run_local_scan, scan_single_file
from hscanner.store import open_global_store


class _SpyVTClient:
    """VirusTotal-shaped spy — records whether upload_file was ever invoked."""

    info = EngineInfo(id="virustotal", display_name="VirusTotal", default_per_minute=4)

    def __init__(self) -> None:
        self.uploaded = False

    async def get_file_report(self, sha: str):  # noqa: ANN201
        return None

    async def upload_file(self, path):  # noqa: ANN001, ANN201
        self.uploaded = True
        return "x"

    async def wait_for_analysis(self, analysis_id: str, sha: str):  # noqa: ANN201
        return EngineFileReport()


class _SpyMDClient:
    """MetaDefender-shaped spy — records whether upload_file was ever invoked."""

    info = EngineInfo(id="metadefender", display_name="MetaDefender", default_per_minute=10)

    def __init__(self) -> None:
        self.uploaded = False

    async def get_file_report(self, sha: str):  # noqa: ANN201
        return None

    async def upload_file(self, path):  # noqa: ANN001, ANN201
        self.uploaded = True
        return "data_id_x"

    async def wait_for_analysis(self, analysis_id: str, sha: str):  # noqa: ANN201
        return EngineFileReport()


# Keep the original _SpyClient alias so any external references still resolve.
_SpyClient = _SpyVTClient


def test_sensitive_local_inventory_never_hashes_file(tmp_path):
    (tmp_path / "secret.pem").write_text("-----BEGIN KEY-----")

    result = run_local_scan(tmp_path)[0]

    assert result.sha256 is None
    assert result.outcome == ScanOutcome.SKIPPED
    assert result.outcome_reason == OutcomeReason.SENSITIVE


@pytest.mark.parametrize(
    "spy_factory",
    [_SpyVTClient, _SpyMDClient],
    ids=["virustotal", "metadefender"],
)
async def test_sensitive_file_is_never_uploaded(tmp_path, monkeypatch, spy_factory):
    """scan_single_file raises SingleFileNotEligible for a sensitive file
    AND the spy engine's upload_file is never called, for both engine shapes."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    (tmp_path / "secret.pem").write_text("-----BEGIN KEY-----")
    spy = spy_factory()

    with pytest.raises(SingleFileNotEligible) as exc_info:
        await scan_single_file(
            tmp_path,
            "secret.pem",
            spy,
            EngineCache(open_global_store(base_dir=tmp_path / "state" / "hscanner")),
        )

    assert exc_info.value.reason == "sensitive"
    assert spy.uploaded is False, "upload_file must never be called for a sensitive file"
