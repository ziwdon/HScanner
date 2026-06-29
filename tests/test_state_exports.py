import json
from pathlib import Path

from hscanner.models import Classification, ClassificationBucket, FileRecord, FileResult
from hscanner.report import export_report_json
from hscanner.state import file_state_key, new_scan_id


def test_scan_id_is_generated() -> None:
    assert new_scan_id().startswith("scan_")


def test_file_state_key_changes_when_file_changes() -> None:
    first = file_state_key("tool.sh", size=1, mtime_ns=100, sha256="a")
    second = file_state_key("tool.sh", size=2, mtime_ns=100, sha256="a")

    assert first != second


def test_export_report_json_writes_no_api_key(tmp_path) -> None:
    record = FileRecord(Path("/scan"), Path("/scan/tool.sh"), 10, 1, 0o100755, False, True, False)
    result = FileResult(
        record=record,
        classification=Classification(
            ClassificationBucket.UPLOAD_CANDIDATE,
            "script",
            upload_eligible=True,
            hash_eligible=True,
            suspicious=True,
        ),
        sha256="abc",
    )
    output = tmp_path / "report.json"

    export_report_json([result], output)

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["files"][0]["relative_path"] == "tool.sh"
    assert "api_key" not in output.read_text(encoding="utf-8")
