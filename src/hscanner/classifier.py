from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from hscanner.models import Classification, ClassificationBucket, FileRecord, OutcomeReason

_ELF_MAGIC = b"\x7fELF"
_SHEBANG = b"#!"


def classify_file(record: FileRecord, policy: dict[str, Any]) -> Classification:
    if record.is_symlink or not record.is_regular:
        return Classification(
            bucket=ClassificationBucket.SKIPPED,
            reason="non-regular file or symlink",
            upload_eligible=False,
            hash_eligible=False,
            skip_reason=OutcomeReason.UNSUPPORTED_FILE,
        )

    basename = record.path.name
    ext = _extension(record.path)
    buckets = policy["buckets"]

    if _matches_rule(basename, ext, buckets["sensitive"]):
        return Classification(
            bucket=ClassificationBucket.SKIPPED,
            reason=f"sensitive pattern matched: {basename}",
            upload_eligible=False,
            hash_eligible=False,
            skip_reason=OutcomeReason.SENSITIVE,
        )

    if _matches_rule(basename, ext, buckets["skipped"]):
        return Classification(
            bucket=ClassificationBucket.SKIPPED,
            reason=f"low-risk skipped pattern matched: {basename}",
            upload_eligible=False,
            hash_eligible=False,
            skip_reason=OutcomeReason.LOW_RISK,
        )

    soft_limit = policy["size_limits"]["large_upload_soft_block_mb"] * 1024 * 1024
    absolute_limit = policy["size_limits"]["absolute_upload_block_mb"] * 1024 * 1024
    upload_like = _is_upload_like(record, ext, buckets["upload_candidate"])

    if record.size > absolute_limit:
        return Classification(
            bucket=ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED
            if upload_like
            else ClassificationBucket.HASH_ONLY,
            reason="file exceeds absolute upload block" if upload_like else "large file hash-only",
            upload_eligible=False,
            hash_eligible=True,
            suspicious=upload_like,
        )

    if record.size > soft_limit:
        return Classification(
            bucket=ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED
            if upload_like
            else ClassificationBucket.HASH_ONLY,
            reason="file exceeds soft upload block" if upload_like else "large file hash-only",
            upload_eligible=False,
            hash_eligible=True,
            suspicious=upload_like,
        )

    if _matches_suspicious_block(record, ext, buckets["suspicious_upload_blocked"]):
        return Classification(
            bucket=ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED,
            reason="suspicious upload-blocked rule matched",
            upload_eligible=False,
            hash_eligible=True,
            suspicious=True,
        )

    if upload_like:
        return Classification(
            bucket=ClassificationBucket.UPLOAD_CANDIDATE,
            reason=buckets["upload_candidate"]["reason"],
            upload_eligible=True,
            hash_eligible=True,
            suspicious=True,
        )

    if ext in set(buckets["hash_only"].get("extensions", [])):
        return Classification(
            bucket=ClassificationBucket.HASH_ONLY,
            reason=buckets["hash_only"]["reason"],
            upload_eligible=False,
            hash_eligible=True,
        )

    return Classification(
        bucket=ClassificationBucket.HASH_ONLY,
        reason="default fallback hash-only",
        upload_eligible=False,
        hash_eligible=True,
    )


def _extension(path: Path) -> str:
    name = path.name
    if name.startswith(".") and name.count(".") == 1:
        return ""
    return path.suffix


def _matches_rule(basename: str, ext: str, rule: dict[str, Any]) -> bool:
    if ext in set(rule.get("extensions", [])):
        return True
    return any(fnmatchcase(basename, pattern) for pattern in rule.get("filename_patterns", []))


def _is_upload_like(record: FileRecord, ext: str, rule: dict[str, Any]) -> bool:
    extensions = {e.lower() for e in rule.get("extensions", [])}
    if ext.lower() in extensions:
        return True
    executable_bits = 0o111
    return bool(rule.get("executable_bit")) and bool(record.mode & executable_bits)


def _matches_suspicious_block(record: FileRecord, ext: str, rules: dict[str, Any]) -> bool:
    size_mb = record.size / (1024 * 1024)
    for rule in rules.get("rules", []):
        if rule.get("extension") == ext and size_mb >= rule.get("min_size_mb", float("inf")):
            return True
    return False


def file_signals(prefix: bytes, mode: int) -> dict[str, bool]:
    return {
        "executable_bit": bool(mode & 0o111),
        "elf": prefix.startswith(_ELF_MAGIC),
        "shebang": prefix.startswith(_SHEBANG),
    }


def reclassify_with_signals(
    record: FileRecord, classification: Classification, prefix: bytes, policy: dict[str, Any]
) -> Classification:
    if classification.bucket != ClassificationBucket.HASH_ONLY:
        return classification
    signals = file_signals(prefix, record.mode)
    if not (signals["elf"] or signals["shebang"]):
        return classification
    soft = policy["size_limits"]["large_upload_soft_block_mb"] * 1024 * 1024
    absolute = policy["size_limits"]["absolute_upload_block_mb"] * 1024 * 1024
    if record.size > soft or record.size > absolute:
        return Classification(
            bucket=ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED,
            reason="executable content over upload size limit",
            upload_eligible=False, hash_eligible=True, suspicious=True,
        )
    return Classification(
        bucket=ClassificationBucket.UPLOAD_CANDIDATE,
        reason="executable content (ELF/shebang) detected",
        upload_eligible=True, hash_eligible=True, suspicious=True,
    )
