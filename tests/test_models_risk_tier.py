from hscanner.models import ClassificationBucket as B
from hscanner.models import RiskTier, risk_tier_for


def test_priority_buckets():
    assert risk_tier_for(B.UPLOAD_CANDIDATE) == RiskTier.PRIORITY
    assert risk_tier_for(B.SUSPICIOUS_UPLOAD_BLOCKED) == RiskTier.PRIORITY


def test_low_risk_and_skipped():
    assert risk_tier_for(B.HASH_ONLY) == RiskTier.LOW_RISK
    assert risk_tier_for(B.SKIPPED) == RiskTier.SKIPPED
