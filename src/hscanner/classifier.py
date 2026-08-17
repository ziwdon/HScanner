from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from hscanner.models import (
    Classification,
    ClassificationBucket,
    FileRecord,
    OutcomeReason,
    RiskTier,
)

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
            risk_tier=RiskTier.SKIPPED,
        )

    basename = record.path.name
    match_basename = basename.lower()
    ext = _extension(record.path).lower()
    buckets = policy["buckets"]

    if _matches_rule(match_basename, ext, buckets["sensitive"]):
        return Classification(
            bucket=ClassificationBucket.SKIPPED,
            reason=f"sensitive pattern matched: {basename}",
            upload_eligible=False,
            hash_eligible=False,
            skip_reason=OutcomeReason.SENSITIVE,
            risk_tier=RiskTier.SKIPPED,
        )

    if _matches_rule(match_basename, ext, buckets["skipped"]):
        return Classification(
            bucket=ClassificationBucket.SKIPPED,
            reason=f"low-risk skipped pattern matched: {basename}",
            upload_eligible=False,
            hash_eligible=False,
            skip_reason=OutcomeReason.LOW_RISK,
            risk_tier=RiskTier.SKIPPED,
        )

    soft_limit = policy["size_limits"]["large_upload_soft_block_mb"] * 1024 * 1024
    absolute_limit = policy["size_limits"]["absolute_upload_block_mb"] * 1024 * 1024

    # Check upload_candidate by EXTENSION only (not executable_bit) first.
    # The executable_bit fallback is applied later, after hash_only, so that
    # known data/config files (e.g. .ini, .json) with a stray exec bit are
    # NOT promoted to HIGH — only truly unknown extensions are.
    matched, tier_key = _is_upload_like_ext(record, ext, buckets["upload_candidate"])
    upload_like_tier = _tier_from_key(tier_key) if matched else None

    if record.size > absolute_limit and matched:
        return _suspicious_blocked(
            "file exceeds absolute upload block",
            tier=upload_like_tier or RiskTier.HIGH,
        )
    if record.size > soft_limit and matched:
        return _suspicious_blocked(
            "file exceeds soft upload block",
            tier=upload_like_tier or RiskTier.HIGH,
        )

    suspicious_tier = _matches_suspicious_block(record, ext, buckets["suspicious_upload_blocked"])
    if suspicious_tier is not None:
        return _suspicious_blocked(
            "suspicious upload-blocked rule matched",
            tier=suspicious_tier,
        )

    if matched:
        return Classification(
            bucket=ClassificationBucket.UPLOAD_CANDIDATE,
            reason=buckets["upload_candidate"]["reason"],
            upload_eligible=True,
            hash_eligible=True,
            suspicious=True,
            risk_tier=upload_like_tier or RiskTier.HIGH,
        )

    # Known data/config/markup/docs/media files stay LOW_RISK even if they
    # have a stray executable bit. ELF/shebang promotion via
    # reclassify_with_signals handles real executable content later.
    if ext in _normalized_extensions(buckets["hash_only"].get("extensions", [])):
        return Classification(
            bucket=ClassificationBucket.HASH_ONLY,
            reason=buckets["hash_only"]["reason"],
            upload_eligible=False,
            hash_eligible=True,
            risk_tier=RiskTier.LOW_RISK,
        )

    # Executable bit on a truly unknown extension → HIGH (worst-case).
    if _has_executable_bit(record, buckets["upload_candidate"]):
        return Classification(
            bucket=ClassificationBucket.UPLOAD_CANDIDATE,
            reason=buckets["upload_candidate"]["reason"],
            upload_eligible=True,
            hash_eligible=True,
            suspicious=True,
            risk_tier=RiskTier.HIGH,
        )

    if record.size > soft_limit or record.size > absolute_limit:
        return _suspicious_blocked(
            "unknown file type exceeds upload size limit",
            tier=RiskTier.HIGH,
        )

    default_bucket = str(policy.get("matching", {}).get("default_bucket", "hash_only")).lower()
    if default_bucket == "upload_candidate":
        return Classification(
            bucket=ClassificationBucket.UPLOAD_CANDIDATE,
            reason="default fallback upload candidate",
            upload_eligible=True,
            hash_eligible=True,
            suspicious=True,
            risk_tier=RiskTier.HIGH,
        )
    return Classification(
        bucket=ClassificationBucket.HASH_ONLY,
        reason="default fallback hash-only",
        upload_eligible=False,
        hash_eligible=True,
        risk_tier=RiskTier.LOW_RISK,
    )


def _suspicious_blocked(reason: str, *, tier: RiskTier) -> Classification:
    return Classification(
        bucket=ClassificationBucket.SUSPICIOUS_UPLOAD_BLOCKED,
        reason=reason,
        upload_eligible=False,
        hash_eligible=True,
        suspicious=True,
        risk_tier=tier,
    )


def _tier_from_key(key: str | None) -> RiskTier:
    return RiskTier.HIGH if key == "high" else RiskTier.MEDIUM


def _extension(path: Path) -> str:
    name = path.name
    if name.startswith(".") and name.count(".") == 1:
        return ""
    return path.suffix


def _matches_rule(basename: str, ext: str, rule: dict[str, Any]) -> bool:
    if ext in _normalized_extensions(rule.get("extensions", [])):
        return True
    return any(
        fnmatchcase(basename, pattern.lower())
        for pattern in rule.get("filename_patterns", [])
    )


def _is_upload_like_ext(
    record: FileRecord, ext: str, rule: dict[str, Any]
) -> tuple[bool, str | None]:
    """Check upload_candidate by EXTENSION only (high/medium), NOT by
    executable_bit. The executable_bit fallback is handled separately by
    ``_has_executable_bit`` so that known hash_only extensions with a
    stray exec bit are not promoted."""
    high = _normalized_extensions(rule.get("high_extensions", []))
    medium = _normalized_extensions(rule.get("medium_extensions", []))
    if ext in high:
        return True, "high"
    if ext in medium:
        return True, "medium"
    return False, None


def _has_executable_bit(record: FileRecord, rule: dict[str, Any]) -> bool:
    return bool(rule.get("executable_bit")) and bool(record.mode & 0o111)


def _matches_suspicious_block(
    record: FileRecord, ext: str, rules: dict[str, Any]
) -> RiskTier | None:
    size_mb = record.size / (1024 * 1024)
    for rule in rules.get("rules", []):
        rule_ext = str(rule.get("extension", "")).lower()
        if rule_ext == ext and size_mb >= rule.get("min_size_mb", float("inf")):
            return _rule_tier(rule)
    return None


def _rule_tier(rule: dict[str, Any]) -> RiskTier:
    # Default: MEDIUM. The default policy's only suspicious-block rule is
    # the `.pak` + executable_markers rule (treated as MEDIUM attention
    # because the inner content is unverified). Oversized-anonymous
    # fallbacks in classify_file set RiskTier.HIGH directly without going
    # through this helper. Future rules wanting HIGH can set `tier: high`.
    tier = str(rule.get("tier", "medium")).lower()
    return RiskTier.HIGH if tier == "high" else RiskTier.MEDIUM


def _matches_executable_marker_block(
    record: FileRecord,
    signals: dict[str, bool],
    policy: dict[str, Any],
) -> RiskTier | None:
    ext = _extension(record.path).lower()
    for rule in policy["buckets"]["suspicious_upload_blocked"].get("rules", []):
        rule_ext = str(rule.get("extension", "")).lower()
        if (
            rule_ext == ext
            and rule.get("executable_markers") is True
            and (signals["elf"] or signals["shebang"])
        ):
            return _rule_tier(rule)
    return None


def _normalized_extensions(extensions: list[str]) -> set[str]:
    return {extension.lower() for extension in extensions}


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
    suspicious_tier = _matches_executable_marker_block(record, signals, policy)
    if suspicious_tier is not None:
        return _suspicious_blocked(
            "executable marker in upload-blocked file type",
            tier=suspicious_tier,
        )
    soft = policy["size_limits"]["large_upload_soft_block_mb"] * 1024 * 1024
    absolute = policy["size_limits"]["absolute_upload_block_mb"] * 1024 * 1024
    if record.size > soft or record.size > absolute:
        return _suspicious_blocked(
            "executable content over upload size limit",
            tier=RiskTier.HIGH,
        )
    return Classification(
        bucket=ClassificationBucket.UPLOAD_CANDIDATE,
        reason="executable content (ELF/shebang) detected",
        upload_eligible=True, hash_eligible=True, suspicious=True,
        risk_tier=RiskTier.HIGH,
    )
