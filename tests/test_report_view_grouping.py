from pathlib import Path

import pytest

from hscanner.classifier import classify_file
from hscanner.models import FileRecord, FileResult
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