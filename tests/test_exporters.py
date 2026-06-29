import csv
import io
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hscanner.exporters import export_report, render_csv, render_html, render_json
from hscanner.models import (
    Classification,
    ClassificationBucket,
    EngineState,
    FileRecord,
    FileResult,
    LookupStatus,
    ReportAction,
)
from hscanner.report import build_scan_report, classify_report_result


@pytest.fixture
def report():
    root = Path("/scan")
    result = FileResult(
        record=FileRecord(
            root=root,
            path=root / "=cmd<script>.sh",
            size=10,
            mtime_ns=1,
            mode=0o100755,
            is_symlink=False,
            is_regular=True,
            is_hidden=False,
        ),
        classification=Classification(
            bucket=ClassificationBucket.UPLOAD_CANDIDATE,
            reason="<script>",
            upload_eligible=True,
            hash_eligible=True,
            suspicious=True,
        ),
        sha256="a" * 64,
        engine_state=EngineState.FOUND,
        lookup_status=LookupStatus.FOUND,
        action=ReportAction.LOOKUP_FOUND,
        engine_stats={"malicious": 1, "suspicious": 0, "undetected": 69},
        detections=[
            {"engine": "Engine A", "category": "malicious", "name": "Trojan.A"}
        ],
        raw_result={"data": {"attributes": {"last_analysis_date": 1_718_886_000}}},
        last_analysis_at=1_718_886_000,
        assessment_complete=True,
    )
    classify_report_result(result)
    return build_scan_report(
        root,
        [result],
        online=True,
        upload_consent=False,
        report_id_factory=lambda: "report-id",
        now=lambda: datetime(2026, 6, 20, tzinfo=UTC),
    )


def test_json_is_canonical_report(report) -> None:
    payload = json.loads(render_json(report))
    assert payload["schema_version"] == 3
    assert payload["files"][0]["raw_result"] == report.files[0].raw_result


def test_csv_has_one_sanitized_row_per_file(report) -> None:
    text = render_csv(report)
    rows = list(csv.DictReader(io.StringIO(text)))
    assert len(rows) == len(report.files)
    assert rows[0]["relative_path"].startswith("'")
    assert json.loads(rows[0]["detections"])[0]["engine"] == "Engine A"
    assert "raw_result" not in rows[0]


def test_csv_export_includes_engine_id_column_and_value(report) -> None:
    file = replace(report.files[0], engine_id="virustotal")

    rows = list(
        csv.DictReader(io.StringIO(render_csv(replace(report, files=(file,)))))
    )

    assert rows[0]["engine_id"] == "virustotal"


def test_csv_uses_outcome_schema_fields(report) -> None:
    row = next(csv.DictReader(io.StringIO(render_csv(report))))

    assert {
        "summary_scanned", "summary_infected", "summary_needs_attention",
        "outcome", "outcome_reason", "lookup_status", "upload_status", "engine_checked",
    } <= row.keys()
    assert {
        "summary_hashed", "summary_known_to_vt", "risk_label",
        "report_category", "action", "engine_state",
    }.isdisjoint(row.keys())


def test_csv_guards_new_and_technical_fields_against_spreadsheet_injection(report) -> None:
    file = replace(
        report.files[0],
        outcome_reason="=dangerous",
        classification_reason="+formula",
    )
    row = next(csv.DictReader(io.StringIO(render_csv(replace(report, files=(file,))))))

    assert row["outcome_reason"].startswith("'")
    assert row["classification_reason"].startswith("'")


def test_html_is_self_contained_and_escaped(report) -> None:
    html = render_html(report)
    assert "HSCANNER TRIAGE REPORT" in html
    assert "<style>" in html
    assert "<details" in html
    assert "&lt;script&gt;" in html
    assert "<script" not in html
    assert "@import" not in html
    assert "src=" not in html
    assert report.files[0].json_reference in html


def test_html_export_shows_engine_provenance(report) -> None:
    file = replace(report.files[0], engine_id="virustotal")
    combined = replace(
        report,
        engine_id="combined",
        engine_name="Combined",
        files=(file,),
        engine_breakdown={"virustotal": 1},
    )

    html = render_html(combined)

    assert "Scan engine" in html
    assert "virustotal: 1" in html


def test_html_export_does_not_apply_web_secondary_row_cap(report) -> None:
    base = replace(report.files[0], report_category="no_detections", risk_label="no_detections")
    files = tuple(
        replace(
            base,
            index=index,
            relative_path=f"file-{index}.bin",
            json_reference=f"/files/{index}/raw_result",
        )
        for index in range(501)
    )
    html = render_html(replace(report, files=files))
    assert "file-500.bin" in html


def test_atomic_failure_preserves_existing_destination(tmp_path, report, monkeypatch) -> None:
    output = tmp_path / "report.json"
    output.write_text("original", encoding="utf-8")

    def _boom(value):
        raise ValueError("bad")

    monkeypatch.setattr("hscanner.exporters.render_json", _boom)

    with pytest.raises(ValueError, match="bad"):
        export_report(report, output)

    assert output.read_text(encoding="utf-8") == "original"
