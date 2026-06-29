from pathlib import Path

from hscanner.classifier import classify_file
from hscanner.models import ClassificationBucket, FileRecord
from hscanner.policy.loader import load_default_policy


def _record(name: str, size: int = 1000, mode: int = 0o644) -> FileRecord:
    root = Path("/scan")
    return FileRecord(
        root=root, path=root / name, size=size, mtime_ns=0, mode=mode,
        is_symlink=False, is_regular=True, is_hidden=False,
    )


def test_new_windows_and_linux_extensions_are_priority():
    policy = load_default_policy()
    for name in ("a.exe", "a.dll", "a.msi", "a.ps1", "a.bat", "a.pyc", "a.run"):
        c = classify_file(_record(name), policy)
        assert c.bucket == ClassificationBucket.UPLOAD_CANDIDATE, name


def test_appimage_extension_is_case_insensitive():
    policy = load_default_policy()
    assert classify_file(_record("Tool.AppImage"), policy).bucket == \
        ClassificationBucket.UPLOAD_CANDIDATE
    assert classify_file(_record("tool.appimage"), policy).bucket == \
        ClassificationBucket.UPLOAD_CANDIDATE
