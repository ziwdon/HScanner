from pathlib import Path

from hscanner.classifier import classify_file
from hscanner.models import FileRecord, RiskTier, risk_tier_for_classification
from hscanner.policy.loader import load_default_policy
from hscanner.scanner import _TIER_ORDER


def _record(name: str, mode: int = 0o100644) -> FileRecord:
    return FileRecord(
        root=Path("/scan"), path=Path("/scan") / name,
        size=10, mtime_ns=1, mode=mode,
        is_symlink=False, is_regular=True, is_hidden=False,
    )


def test_tier_order_ranks_high_before_medium_before_low_risk_before_skipped():
    assert _TIER_ORDER[RiskTier.HIGH] < _TIER_ORDER[RiskTier.MEDIUM]
    assert _TIER_ORDER[RiskTier.MEDIUM] < _TIER_ORDER[RiskTier.LOW_RISK]
    assert _TIER_ORDER[RiskTier.LOW_RISK] < _TIER_ORDER[RiskTier.SKIPPED]


def test_priority_sort_key_places_high_before_medium_alphabetically_reversed():
    policy = load_default_policy()
    py_cls = classify_file(_record("z.py"), policy)
    sh_cls = classify_file(_record("a.sh"), policy)
    key_py = (_TIER_ORDER[risk_tier_for_classification(py_cls)], "z.py")
    key_sh = (_TIER_ORDER[risk_tier_for_classification(sh_cls)], "a.sh")
    # HIGH ahead of MEDIUM even though "a.sh" < "z.py" alphabetically.
    assert key_sh < key_py


def test_low_risk_below_high_and_medium():
    policy = load_default_policy()
    pdf_cls = classify_file(_record("a.pdf"), policy)
    tier = risk_tier_for_classification(pdf_cls)
    assert _TIER_ORDER[tier] > _TIER_ORDER[RiskTier.MEDIUM]
    assert _TIER_ORDER[tier] > _TIER_ORDER[RiskTier.HIGH]