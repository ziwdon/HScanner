from pathlib import Path

from hscanner.classifier import classify_file, file_signals, reclassify_with_signals
from hscanner.models import ClassificationBucket, FileRecord, RiskTier
from hscanner.policy.loader import load_default_policy


def _record(name: str, size: int = 1000, mode: int = 0o644) -> FileRecord:
    root = Path("/scan")
    return FileRecord(root=root, path=root / name, size=size, mtime_ns=0, mode=mode,
                      is_symlink=False, is_regular=True, is_hidden=False)


def test_file_signals_detects_elf_and_shebang():
    assert file_signals(b"\x7fELF\x02\x01", 0o644) == {
        "executable_bit": False, "elf": True, "shebang": False}
    assert file_signals(b"#!/bin/sh\n", 0o644)["shebang"] is True
    assert file_signals(b"plain text", 0o755)["executable_bit"] is True


def test_extensionless_unknown_file_is_hash_only_then_promotes_with_elf():
    policy = load_default_policy()
    rec = _record("launcher")  # no extension, no executable bit
    base = classify_file(rec, policy)
    assert base.bucket == ClassificationBucket.HASH_ONLY
    assert base.risk_tier == RiskTier.LOW_RISK
    promoted = reclassify_with_signals(rec, base, b"\x7fELF\x02", policy)
    assert promoted is not base
    assert promoted.bucket == ClassificationBucket.UPLOAD_CANDIDATE
    assert promoted.risk_tier == RiskTier.HIGH


def test_oversize_elf_promotes_to_upload_blocked_high():
    policy = load_default_policy()
    huge = policy["size_limits"]["absolute_upload_block_mb"] * 1024 * 1024 + 1
    rec = _record("launcher", size=huge)
    base = classify_file(rec, policy)
    assert base.bucket == ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED
    promoted = reclassify_with_signals(rec, base, b"#!/bin/sh\n", policy)
    # base is not HASH_ONLY so reclassify returns it unchanged
    assert promoted is base
    assert promoted.risk_tier == RiskTier.HIGH


def test_pak_with_executable_marker_promotes_to_medium_suspicious_blocked():
    policy = load_default_policy()
    rec = _record("game.pak")
    base = classify_file(rec, policy)
    assert base.bucket == ClassificationBucket.HASH_ONLY
    assert base.risk_tier == RiskTier.LOW_RISK

    promoted = reclassify_with_signals(rec, base, b"\x7fELF\x02", policy)

    assert promoted.bucket == ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED
    assert promoted.risk_tier == RiskTier.MEDIUM
    assert promoted.upload_eligible is False
    assert promoted.hash_eligible is True


def test_plain_pak_without_executable_marker_stays_hash_only():
    policy = load_default_policy()
    rec = _record("game.pak")
    base = classify_file(rec, policy)

    unchanged = reclassify_with_signals(rec, base, b"plain asset data", policy)

    assert unchanged is base


def test_non_hash_only_unchanged():
    policy = load_default_policy()
    rec = _record("x.sh")
    base = classify_file(rec, policy)  # already upload_candidate
    assert base.risk_tier == RiskTier.HIGH
    assert reclassify_with_signals(rec, base, b"#!/bin/sh\n", policy) is base
