import tempfile
from pathlib import Path

import pytest

from hscanner.engines.metadefender import MetaDefenderEngine
from hscanner.errors import ErrorCode, HScannerError
from hscanner.models import (
    Classification,
    ClassificationBucket,
    FileRecord,
    FileResult,
    LookupStatus,
    ScanOutcome,
)
from hscanner.report import classify_report_result

_MD = "https://api.metadefender.com/v4"


def _found_body(detected, total):
    return {
        "data_id": "DID",
        "scan_results": {
            "progress_percentage": 100,
            "total_detected_avs": detected,
            "total_avs": total,
            "scan_all_result_i": 1 if detected else 0,
            "scan_all_result_a": "Infected" if detected else "No Threat Detected",
            "scan_details": (
                {"ACME": {"threat_found": "Win.Trojan", "scan_result_i": 1}} if detected else {}
            ),
        },
        "file_info": {"sha256": "abc"},
    }


@pytest.mark.asyncio
async def test_hash_found_normalizes(httpx_mock):
    httpx_mock.add_response(url=f"{_MD}/hash/abc", json=_found_body(2, 30))
    engine = MetaDefenderEngine("k")
    report = await engine.get_file_report("abc")
    await engine.close()
    assert report is not None
    assert report.engine_stats == {"malicious": 2, "undetected": 28}
    assert report.detections == [
        {"engine": "ACME", "category": "malicious", "name": "Win.Trojan"}
    ]
    assert report.permalink == "https://metadefender.com/results/hash/abc"
    assert report.assessment_complete is True


@pytest.mark.asyncio
async def test_hash_found_uses_process_info_progress_when_scan_results_omits_progress(
    httpx_mock,
):
    body = _found_body(0, 2)
    del body["scan_results"]["progress_percentage"]
    body["process_info"] = {"progress_percentage": 100}
    httpx_mock.add_response(url=f"{_MD}/hash/abc", json=body)
    engine = MetaDefenderEngine("k")
    report = await engine.get_file_report("abc")
    await engine.close()

    assert report is not None
    assert report.engine_stats == {"malicious": 0, "undetected": 2}
    assert report.assessment_complete is True


@pytest.mark.asyncio
async def test_hash_found_uses_terminal_aggregate_result_when_progress_is_absent(
    httpx_mock,
):
    body = _found_body(0, 2)
    del body["scan_results"]["progress_percentage"]
    httpx_mock.add_response(url=f"{_MD}/hash/abc", json=body)
    engine = MetaDefenderEngine("k")
    report = await engine.get_file_report("abc")
    await engine.close()

    assert report is not None
    assert report.engine_stats == {"malicious": 0, "undetected": 2}
    assert report.assessment_complete is True


@pytest.mark.asyncio
async def test_hash_found_counts_only_without_terminal_status_stays_incomplete(httpx_mock):
    body = _found_body(0, 2)
    del body["scan_results"]["progress_percentage"]
    del body["scan_results"]["scan_all_result_i"]
    del body["scan_results"]["scan_all_result_a"]
    httpx_mock.add_response(url=f"{_MD}/hash/abc", json=body)
    engine = MetaDefenderEngine("k")
    report = await engine.get_file_report("abc")
    await engine.close()

    assert report is not None
    assert report.engine_stats == {"malicious": 0, "undetected": 2}
    assert report.assessment_complete is False


@pytest.mark.asyncio
async def test_hash_found_malformed_aggregate_code_without_label_stays_incomplete(
    httpx_mock,
):
    body = _found_body(0, 2)
    del body["scan_results"]["progress_percentage"]
    del body["scan_results"]["scan_all_result_a"]
    body["scan_results"]["scan_all_result_i"] = "unknown"
    httpx_mock.add_response(url=f"{_MD}/hash/abc", json=body)
    engine = MetaDefenderEngine("k")
    report = await engine.get_file_report("abc")
    await engine.close()

    assert report is not None
    assert report.assessment_complete is False


@pytest.mark.asyncio
async def test_hash_found_unknown_numeric_aggregate_code_without_label_stays_incomplete(
    httpx_mock,
):
    body = _found_body(0, 2)
    del body["scan_results"]["progress_percentage"]
    del body["scan_results"]["scan_all_result_a"]
    body["scan_results"]["scan_all_result_i"] = 2
    httpx_mock.add_response(url=f"{_MD}/hash/abc", json=body)
    engine = MetaDefenderEngine("k")
    report = await engine.get_file_report("abc")
    await engine.close()

    assert report is not None
    assert report.assessment_complete is False


@pytest.mark.asyncio
async def test_terminal_no_threat_hash_result_maps_to_no_detections_report_outcome(
    httpx_mock,
):
    body = _found_body(0, 1)
    del body["scan_results"]["progress_percentage"]
    httpx_mock.add_response(url=f"{_MD}/hash/abc", json=body)
    engine = MetaDefenderEngine("k")
    engine_report = await engine.get_file_report("abc")
    await engine.close()
    record = FileRecord(
        root=Path("/scan"),
        path=Path("/scan/tool.exe"),
        size=1024,
        mtime_ns=1,
        mode=0o100755,
        is_symlink=False,
        is_regular=True,
        is_hidden=False,
    )
    result = classify_report_result(
        FileResult(
            record=record,
            classification=Classification(
                ClassificationBucket.UPLOAD_CANDIDATE,
                "executable, package, or script",
                upload_eligible=True,
                hash_eligible=True,
                suspicious=True,
            ),
            lookup_status=LookupStatus.FOUND,
            assessment_complete=engine_report.assessment_complete,
            engine_stats=dict(engine_report.engine_stats),
            detections=[dict(detection) for detection in engine_report.detections],
        )
    )

    assert result.outcome == ScanOutcome.NO_DETECTIONS


@pytest.mark.asyncio
async def test_hash_not_found_returns_none(httpx_mock):
    httpx_mock.add_response(
        url=f"{_MD}/hash/abc", status_code=404,
        json={"error": {"code": 404008, "messages": ["Not Found"]}},
    )
    engine = MetaDefenderEngine("k")
    assert await engine.get_file_report("abc") is None
    await engine.close()


@pytest.mark.asyncio
async def test_upload_returns_data_id(httpx_mock):
    httpx_mock.add_response(url=f"{_MD}/file", json={"data_id": "DID", "sha256": "abc"})
    engine = MetaDefenderEngine("k")
    with tempfile.NamedTemporaryFile() as f:
        f.write(b"hi")
        f.flush()
        assert await engine.upload_file(Path(f.name)) == "DID"
    await engine.close()


@pytest.mark.asyncio
async def test_poll_until_complete(httpx_mock):
    httpx_mock.add_response(
        url=f"{_MD}/file/DID",
        json={"data_id": "DID", "scan_results": {"progress_percentage": 50}},
    )
    httpx_mock.add_response(url=f"{_MD}/file/DID", json=_found_body(0, 32))
    engine = MetaDefenderEngine("k", poll_interval=0)
    report = await engine.wait_for_analysis("DID", "abc")
    await engine.close()
    assert report.assessment_complete is True
    assert report.engine_stats == {"malicious": 0, "undetected": 32}


@pytest.mark.asyncio
async def test_auth_failure_maps_to_engine_auth_failed(httpx_mock):
    httpx_mock.add_response(url=f"{_MD}/hash/abc", status_code=401)
    engine = MetaDefenderEngine("k")
    with pytest.raises(HScannerError) as exc:
        await engine.get_file_report("abc")
    await engine.close()
    assert exc.value.code == ErrorCode.ENGINE_AUTH_FAILED
