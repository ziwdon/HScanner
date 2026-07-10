from pathlib import Path

from hscanner.classifier import classify_file, file_signals, reclassify_with_signals
from hscanner.models import ClassificationBucket, FileRecord
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


def test_extensionless_unknown_file_is_priority_before_signal_detection():
    policy = load_default_policy()
    rec = _record("launcher")  # no extension, not executable bit
    base = classify_file(rec, policy)
    assert base.bucket == ClassificationBucket.UPLOAD_CANDIDATE
    promoted = reclassify_with_signals(rec, base, b"\x7fELF\x02", policy)
    assert promoted is base


def test_oversize_elf_promotes_to_upload_blocked():
    policy = load_default_policy()
    huge = policy["size_limits"]["absolute_upload_block_mb"] * 1024 * 1024 + 1
    rec = _record("launcher", size=huge)
    base = classify_file(rec, policy)
    promoted = reclassify_with_signals(rec, base, b"#!/bin/sh\n", policy)
    assert promoted.bucket == ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED
    assert promoted.upload_eligible is False


def test_pak_with_executable_marker_promotes_to_upload_blocked():
    policy = load_default_policy()
    rec = _record("game.pak")
    base = classify_file(rec, policy)
    assert base.bucket == ClassificationBucket.HASH_ONLY

    promoted = reclassify_with_signals(rec, base, b"\x7fELF\x02", policy)

    assert promoted.bucket == ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED
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
    assert reclassify_with_signals(rec, base, b"#!/bin/sh\n", policy) is base
