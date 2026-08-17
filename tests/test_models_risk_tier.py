from hscanner.models import (
    Classification,
    RiskTier,
    risk_tier_for_classification,
    risk_tier_for_legacy_bucket,
)
from hscanner.models import (
    ClassificationBucket as B,
)


def test_risk_tier_enum_has_four_members():
    assert {t.value for t in RiskTier} == {"high", "medium", "low_risk", "skipped"}


def test_classification_carries_risk_tier_field():
    cls = Classification(
        bucket=B.HASH_ONLY, reason="x", upload_eligible=False, hash_eligible=True,
        risk_tier=RiskTier.LOW_RISK,
    )
    assert cls.risk_tier == RiskTier.LOW_RISK


def test_risk_tier_for_classification_reads_field():
    cls = Classification(
        bucket=B.UPLOAD_CANDIDATE, reason="x", upload_eligible=True, hash_eligible=True,
        risk_tier=RiskTier.HIGH,
    )
    assert risk_tier_for_classification(cls) == RiskTier.HIGH


def test_classification_default_risk_tier_is_low_risk():
    cls = Classification(
        bucket=B.HASH_ONLY, reason="x", upload_eligible=False, hash_eligible=True,
    )
    assert cls.risk_tier == RiskTier.LOW_RISK


def test_risk_tier_for_legacy_bucket_maps_priority_buckets_to_high():
    assert risk_tier_for_legacy_bucket(B.UPLOAD_CANDIDATE) == RiskTier.HIGH
    assert risk_tier_for_legacy_bucket(B.SUSPICIOUS_UPLOAD_BLOCKED) == RiskTier.HIGH


def test_risk_tier_for_legacy_bucket_maps_hash_only_to_low_risk():
    assert risk_tier_for_legacy_bucket(B.HASH_ONLY) == RiskTier.LOW_RISK


def test_risk_tier_for_legacy_bucket_maps_skipped_to_skipped():
    assert risk_tier_for_legacy_bucket(B.SKIPPED) == RiskTier.SKIPPED