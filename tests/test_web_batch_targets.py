import pytest
from starlette.testclient import TestClient

from hscanner.classifier import classify_file
from hscanner.models import FileRecord, FileResult, LookupStatus, ScanOutcome
from hscanner.policy.loader import load_default_policy
from hscanner.report import build_scan_report
from hscanner.web.app import create_app
from hscanner.web.report_store import ReportRegistry


def _empty_report(report_id: str):
    record = FileRecord(
        root=__import__("pathlib").Path("/scan"),
        path=__import__("pathlib").Path("/scan") / "noop.txt",
        size=10, mtime_ns=0, mode=0o644,
        is_symlink=False, is_regular=True, is_hidden=False,
    )
    cls = classify_file(record, load_default_policy())
    result = FileResult(record=record, classification=cls, lookup_status=LookupStatus.NOT_FOUND)
    result.outcome = ScanOutcome.SKIPPED
    return build_scan_report(
        __import__("pathlib").Path("/scan"),
        [result],
        online=True,
        upload_consent=False,
        report_id_factory=lambda: report_id,
    )


def test_scan_unverified_rejects_unknown_target():
    app = create_app(report_registry=ReportRegistry())
    app.state.report_registry.put(_empty_report("stub"))
    client = TestClient(app)
    response = client.post(
        "/reports/stub/scan-unverified",
        json={"target": "bogus"},
    )
    assert response.status_code == 400
    assert "unknown target" in response.json().get("error", "")


def test_scan_unverified_accepts_high_and_medium_and_priority_targets():
    """The batch endpoint should NOT reject ``high``, ``medium``, or
    ``priority`` (legacy alias). A 202 with empty indices is acceptable —
    we are asserting the target is not rejected by the unknown-target
    guard."""
    app = create_app(report_registry=ReportRegistry())
    app.state.report_registry.put(_empty_report("stub"))
    client = TestClient(app)
    for target in ("all", "high", "medium", "low_risk", "priority"):
        response = client.post(
            "/reports/stub/scan-unverified",
            json={"target": target},
        )
        # Either 400 with "no_key" (fine), 202 with no candidates (fine),
        # or 404 (only if the report isn't actually registered — not the
        # case here). We assert the only failure mode NOT hit is
        # "unknown target".
        if response.status_code == 400:
            assert "unknown target" not in response.json().get("error", ""), target


if __name__ == "__main__":
    pytest.main([__file__, "-v"])