from pathlib import Path

from hscanner.classifier import classify_file
from hscanner.models import ClassificationBucket, FileRecord, RiskTier
from hscanner.policy.loader import load_default_policy


def _record(name: str, size: int = 10, mode: int = 0o100644) -> FileRecord:
    return FileRecord(
        root=Path("/scan"), path=Path("/scan") / name,
        size=size, mtime_ns=1, mode=mode,
        is_symlink=False, is_regular=True, is_hidden=name.startswith("."),
    )


def test_high_extension_match_is_high():
    policy = load_default_policy()
    for name in ("a.exe", "a.dll", "a.so", "a.bin", "a.appimage", "a.deb", "a.rpm",
                 "a.msi", "a.run", "a.scr", "a.com", "a.lnk",
                 "a.sh", "a.bash", "a.zsh", "a.bat", "a.cmd", "a.ps1",
                 "a.vbs", "a.wsf"):
        c = classify_file(_record(name), policy)
        assert c.bucket == ClassificationBucket.UPLOAD_CANDIDATE, name
        assert c.risk_tier == RiskTier.HIGH, name
        assert c.upload_eligible is True, name


def test_medium_extension_match_is_medium():
    policy = load_default_policy()
    for name in ("a.py", "a.pyc", "a.pyd", "a.rpy", "a.rpym", "a.rpyc",
                 "a.rpymc", "a.rpyb", "a.rpa",
                 "a.pl", "a.rb", "a.js", "a.jar"):
        c = classify_file(_record(name), policy)
        assert c.bucket == ClassificationBucket.UPLOAD_CANDIDATE, name
        assert c.risk_tier == RiskTier.MEDIUM, name
        assert c.upload_eligible is True, name


def test_executable_bit_on_unknown_extension_is_high():
    policy = load_default_policy()
    c = classify_file(_record("weird.xyz", mode=0o100755), policy)
    assert c.bucket == ClassificationBucket.UPLOAD_CANDIDATE
    assert c.risk_tier == RiskTier.HIGH
    assert c.upload_eligible is True


def test_sensitive_pattern_wins_and_is_skipped_tier():
    policy = load_default_policy()
    c = classify_file(_record(".env"), policy)
    assert c.bucket == ClassificationBucket.SKIPPED
    assert c.risk_tier == RiskTier.SKIPPED


def test_low_risk_skip_extension_is_skipped_tier():
    policy = load_default_policy()
    c = classify_file(_record("readme.txt"), policy)
    assert c.bucket == ClassificationBucket.SKIPPED
    assert c.risk_tier == RiskTier.SKIPPED


def test_hash_only_extension_is_low_risk_tier():
    policy = load_default_policy()
    for name in ("a.pdf", "a.mp4", "a.png", "a.json", "a.xml", "a.yaml",
                 "a.toml", "a.html", "a.css", "a.sql"):
        c = classify_file(_record(name), policy)
        assert c.bucket == ClassificationBucket.HASH_ONLY, name
        assert c.risk_tier == RiskTier.LOW_RISK, name


def test_oversized_high_extension_is_high_suspicious_blocked():
    policy = load_default_policy()
    size = policy["size_limits"]["large_upload_soft_block_mb"] * 1024 * 1024 + 1
    c = classify_file(_record("big.sh", size=size), policy)
    assert c.bucket == ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED
    assert c.risk_tier == RiskTier.HIGH
    assert c.upload_eligible is False
    assert c.hash_eligible is True


def test_oversized_medium_extension_is_medium_suspicious_blocked():
    policy = load_default_policy()
    size = policy["size_limits"]["large_upload_soft_block_mb"] * 1024 * 1024 + 1
    c = classify_file(_record("big.py", size=size), policy)
    assert c.bucket == ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED
    assert c.risk_tier == RiskTier.MEDIUM
    assert c.upload_eligible is False
    assert c.hash_eligible is True