from pathlib import Path

from hscanner.classifier import classify_file
from hscanner.models import ClassificationBucket, FileRecord, RiskTier
from hscanner.policy.loader import load_default_policy


def _record(name: str) -> FileRecord:
    return FileRecord(
        root=Path("/scan"), path=Path("/scan") / name,
        size=10, mtime_ns=1, mode=0o100644,
        is_symlink=False, is_regular=True, is_hidden=False,
    )


def test_unrecognized_extension_falls_back_to_hash_only_low_risk():
    """The catch-all MUST honor matching.default_bucket (default hash_only)."""
    policy = load_default_policy()
    c = classify_file(_record("data.unknownext"), policy)
    assert c.bucket == ClassificationBucket.HASH_ONLY
    assert c.risk_tier == RiskTier.LOW_RISK
    assert c.upload_eligible is False
    assert c.hash_eligible is True
    assert c.suspicious is False


def test_explicit_default_bucket_upload_candidate_changes_fallback():
    policy = load_default_policy()
    policy = {**policy, "matching": {**policy["matching"], "default_bucket": "upload_candidate"}}
    c = classify_file(_record("data.unknownext"), policy)
    assert c.bucket == ClassificationBucket.UPLOAD_CANDIDATE
    # An unrecognized extension with no executable bit falls back to HIGH
    # (worst-case for unknown upload-candidate default).
    assert c.risk_tier == RiskTier.HIGH
    assert c.upload_eligible is True


def test_unrecognized_oversized_file_is_high_suspicious_blocked():
    policy = load_default_policy()
    size = policy["size_limits"]["large_upload_soft_block_mb"] * 1024 * 1024 + 1
    record = FileRecord(
        root=Path("/scan"), path=Path("/scan") / "blob.unknownext",
        size=size, mtime_ns=1, mode=0o100644,
        is_symlink=False, is_regular=True, is_hidden=False,
    )
    c = classify_file(record, policy)
    assert c.bucket == ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED
    assert c.risk_tier == RiskTier.HIGH