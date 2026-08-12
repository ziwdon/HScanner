from pathlib import Path

import pytest

from hscanner.classifier import classify_file
from hscanner.models import (
    ClassificationBucket,
    FileRecord,
    FileResult,
    LookupStatus,
    OutcomeReason,
    ScanOutcome,
)
from hscanner.policy.loader import load_default_policy
from hscanner.report import build_scan_report, classify_report_result
from hscanner.report_view import build_report_view


def _record(name: str) -> FileRecord:
    root = Path("/scan")
    return FileRecord(
        root=root,
        path=root / name,
        size=100,
        mtime_ns=0,
        mode=0o644,
        is_symlink=False,
        is_regular=True,
        is_hidden=False,
    )


def _classified(rec: FileRecord):
    return classify_file(rec, load_default_policy())


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("foo.exe", "exe"),
        ("lib/bar.sh", "sh"),
        ("run", ""),
        ("Makefile", ""),
        ("archive.tar.gz", "gz"),
        ("UPPER.EXE", "exe"),
    ],
)
def test_build_file_view_exposes_extension(name, expected):
    rec = _record(name)
    cls = _classified(rec)
    res = classify_report_result(FileResult(record=rec, classification=cls))
    report = build_scan_report(Path("/scan"), [res], online=False, upload_consent=False)
    view = build_report_view(report)
    for section in view["sections"]:
        for file in section["files"]:
            if file["name"] == name.split("/")[-1]:
                assert file["extension"] == expected
                return
    pytest.fail(f"file {name!r} not found in any section")


def _needs_attention_result(name: str, bucket: ClassificationBucket):
    rec = _record(name)
    cls = _classified(rec)
    cls.bucket = bucket
    res = classify_report_result(FileResult(
        record=rec, classification=cls,
        lookup_status=LookupStatus.NOT_FOUND,
    ))
    res.outcome = ScanOutcome.NEEDS_ATTENTION
    res.outcome_reason = OutcomeReason.ENGINE_NOT_FOUND
    return res


def test_needs_attention_section_has_priority_and_low_risk_groups():
    results = [
        _needs_attention_result("tool.exe", ClassificationBucket.UPLOAD_CANDIDATE),
        _needs_attention_result("notes.txt", ClassificationBucket.HASH_ONLY),
        _needs_attention_result("big.exe", ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED),
        _needs_attention_result("misc.dat", ClassificationBucket.HASH_ONLY),
    ]
    report = build_scan_report(Path("/scan"), results, online=True, upload_consent=False)
    view = build_report_view(report)

    needs = next(s for s in view["sections"] if s["outcome"] == "needs_attention")
    assert [g["key"] for g in needs["groups"]] == ["priority", "low_risk"]
    priority_names = {f["name"] for f in needs["groups"][0]["files"]}
    low_names = {f["name"] for f in needs["groups"][1]["files"]}
    assert priority_names == {"tool.exe", "big.exe"}
    assert low_names == {"notes.txt", "misc.dat"}
    assert needs["groups"][0]["total"] == 2
    assert needs["groups"][1]["total"] == 2
    for group in needs["groups"]:
        assert group["hidden"] == 0


def test_needs_attention_section_exposes_risk_chips_and_filters():
    results = [
        _needs_attention_result("tool.exe", ClassificationBucket.UPLOAD_CANDIDATE),
        _needs_attention_result("notes.txt", ClassificationBucket.HASH_ONLY),
        _needs_attention_result("big.exe", ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED),
    ]
    report = build_scan_report(Path("/scan"), results, online=True, upload_consent=False)
    view = build_report_view(report)
    needs = next(s for s in view["sections"] if s["outcome"] == "needs_attention")

    chips = needs["risk_chips"]
    assert [c["key"] for c in chips] == ["priority", "low_risk"]
    assert {c["count"] for c in chips} == {2, 1}
    assert all("sev" in c and "label" in c for c in chips)

    filters = needs["filters"]
    assert [f["key"] for f in filters] == ["all", "priority", "low_risk"]
    assert filters[0]["pressed"] is True
    assert all(not f["pressed"] for f in filters[1:])
    assert all("label" in f for f in filters)


def test_infected_and_errors_sections_have_no_groups_key():
    rec = _record("tool.exe")
    cls = _classified(rec)
    res = classify_report_result(FileResult(
        record=rec, classification=cls,
        lookup_status=LookupStatus.NOT_FOUND,
    ))
    res.outcome = ScanOutcome.INFECTED
    res.outcome_reason = OutcomeReason.ENGINE_DETECTION
    report = build_scan_report(Path("/scan"), [res], online=True, upload_consent=False)
    view = build_report_view(report)
    for outcome in ("infected", "error"):
        section = next((s for s in view["sections"] if s["outcome"] == outcome), None)
        if section is None:
            continue
        assert "groups" not in section


def _no_detections_result(name: str):
    rec = _record(name)
    cls = _classified(rec)
    res = classify_report_result(FileResult(
        record=rec, classification=cls,
        lookup_status=LookupStatus.FOUND,
    ))
    res.outcome = ScanOutcome.NO_DETECTIONS
    res.outcome_reason = OutcomeReason.ENGINE_CLEAN
    res.assessment_complete = True
    return res


def test_no_detections_grouped_alphabetically_by_extension():
    results = [
        _no_detections_result("zeta.sh"),
        _no_detections_result("alpha.exe"),
        _no_detections_result("readme"),
        _no_detections_result("beta.exe"),
        _no_detections_result("gamma.dat"),
    ]
    report = build_scan_report(Path("/scan"), results, online=True, upload_consent=False)
    view = build_report_view(report)

    nodet = next(s for s in view["sections"] if s["outcome"] == "no_detections")
    keys = [g["key"] for g in nodet["groups"]]
    assert keys == ["", "dat", "exe", "sh"]
    assert nodet["groups"][0]["title"] == "(no extension)"
    assert nodet["groups"][1]["title"] == ".dat"
    exe_names = {f["name"] for f in next(g for g in nodet["groups"] if g["key"] == "exe")["files"]}
    assert exe_names == {"alpha.exe", "beta.exe"}
    for group in nodet["groups"]:
        assert group["hidden"] == 0


def test_skipped_grouped_with_per_group_cap():
    # 750 .exe files + 200 .sh files
    results = []
    for i in range(750):
        results.append(_no_detections_result(f"a{i}.exe"))
    for i in range(200):
        results.append(_no_detections_result(f"b{i}.sh"))
    for r in results:
        r.outcome = ScanOutcome.SKIPPED
        r.outcome_reason = OutcomeReason.LOW_RISK
    report = build_scan_report(Path("/scan"), results, online=True, upload_consent=False)
    view = build_report_view(report)

    skipped = next(s for s in view["sections"] if s["outcome"] == "skipped")
    groups = {g["key"]: g for g in skipped["groups"]}
    assert set(groups) == {"exe", "sh"}
    assert groups["exe"]["total"] == 750
    assert groups["exe"]["hidden"] == 250
    assert len(groups["exe"]["files"]) == 500
    assert groups["sh"]["total"] == 200
    assert groups["sh"]["hidden"] == 0
    assert len(groups["sh"]["files"]) == 200