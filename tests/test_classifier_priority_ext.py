from pathlib import Path

from hscanner.classifier import classify_file
from hscanner.models import ClassificationBucket, FileRecord, RiskTier
from hscanner.policy.loader import load_default_policy


def _record(name: str, size: int = 1000, mode: int = 0o644) -> FileRecord:
    root = Path("/scan")
    return FileRecord(
        root=root, path=root / name, size=size, mtime_ns=0, mode=mode,
        is_symlink=False, is_regular=True, is_hidden=False,
    )


def test_new_windows_and_linux_extensions_are_priority():
    policy = load_default_policy()
    high_ext = {".exe", ".dll", ".msi", ".ps1", ".bat", ".run"}
    for name in ("a.exe", "a.dll", "a.msi", "a.ps1", "a.bat", "a.pyc", "a.run"):
        c = classify_file(_record(name), policy)
        assert c.bucket == ClassificationBucket.UPLOAD_CANDIDATE, name
        ext = Path(name).suffix.lower()
        expected = RiskTier.HIGH if ext in high_ext else RiskTier.MEDIUM
        assert c.risk_tier == expected, name


def test_appimage_extension_is_case_insensitive():
    policy = load_default_policy()
    for name in ("Tool.AppImage", "tool.appimage"):
        c = classify_file(_record(name), policy)
        assert c.bucket == ClassificationBucket.UPLOAD_CANDIDATE
        assert c.risk_tier == RiskTier.HIGH
