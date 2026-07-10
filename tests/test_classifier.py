from pathlib import Path

from hscanner.classifier import classify_file
from hscanner.models import ClassificationBucket, FileRecord, OutcomeReason
from hscanner.policy.loader import load_default_policy


def record(name: str, size: int = 10, mode: int = 0o100644) -> FileRecord:
    return FileRecord(
        root=Path("/scan"),
        path=Path("/scan") / name,
        size=size,
        mtime_ns=1,
        mode=mode,
        is_symlink=False,
        is_regular=True,
        is_hidden=name.startswith("."),
    )


def test_sensitive_pattern_wins_over_upload_candidate() -> None:
    result = classify_file(record("secrets.sh", mode=0o100755), load_default_policy())

    assert result.bucket == ClassificationBucket.SKIPPED
    assert result.upload_eligible is False
    assert result.hash_eligible is False
    assert result.skip_reason == OutcomeReason.SENSITIVE


def test_sensitive_patterns_are_case_insensitive() -> None:
    policy = load_default_policy()

    for name in ("Secret.py", "MY_SECRETS.sh", "id_rsa.PEM", "KEYS.KEY"):
        result = classify_file(record(name, mode=0o100755), policy)

        assert result.bucket == ClassificationBucket.SKIPPED, name
        assert result.upload_eligible is False, name
        assert result.hash_eligible is False, name
        assert result.skip_reason == OutcomeReason.SENSITIVE, name


def test_env_suffix_files_are_sensitive() -> None:
    policy = load_default_policy()

    for name in (".env.local", ".env.production"):
        result = classify_file(record(name), policy)

        assert result.bucket == ClassificationBucket.SKIPPED, name
        assert result.hash_eligible is False, name
        assert result.skip_reason == OutcomeReason.SENSITIVE, name


def test_low_value_file_has_low_risk_skip_reason() -> None:
    result = classify_file(record("notes.txt"), load_default_policy())

    assert result.bucket == ClassificationBucket.SKIPPED
    assert result.skip_reason == OutcomeReason.LOW_RISK


def test_non_regular_file_has_unsupported_skip_reason() -> None:
    item = record("link")
    item = FileRecord(
        root=item.root,
        path=item.path,
        size=item.size,
        mtime_ns=item.mtime_ns,
        mode=item.mode,
        is_symlink=True,
        is_regular=False,
        is_hidden=item.is_hidden,
    )
    result = classify_file(item, load_default_policy())

    assert result.bucket == ClassificationBucket.SKIPPED
    assert result.skip_reason == OutcomeReason.UNSUPPORTED_FILE


def test_unknown_extension_falls_back_to_hash_only() -> None:
    result = classify_file(record("sample.xyz"), load_default_policy())

    assert result.bucket == ClassificationBucket.HASH_ONLY
    assert result.upload_eligible is False
    assert result.hash_eligible is True


def test_large_upload_candidate_is_upload_blocked() -> None:
    size = 300 * 1024 * 1024
    result = classify_file(record("tool.bin", size=size), load_default_policy())

    assert result.bucket == ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED
    assert result.upload_eligible is False
    assert result.hash_eligible is True
    assert result.suspicious is True


def test_executable_bit_is_upload_candidate() -> None:
    result = classify_file(record("runner", mode=0o100755), load_default_policy())

    assert result.bucket == ClassificationBucket.UPLOAD_CANDIDATE
    assert result.upload_eligible is True


def test_rpyc_bytecode_is_upload_candidate() -> None:
    result = classify_file(record("script.rpyc"), load_default_policy())

    assert result.bucket == ClassificationBucket.UPLOAD_CANDIDATE
    assert result.upload_eligible is True
