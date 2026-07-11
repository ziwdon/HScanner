from copy import deepcopy

import pytest

from hscanner.policy.loader import (
    QuotaPolicy,
    load_default_policy,
    parse_quota_policy,
    validate_policy,
)


def test_parses_default_policy_quota_block():
    q = parse_quota_policy(load_default_policy())
    assert q == QuotaPolicy(
        requests_per_minute=4,
        per_scan_request_budget=None,
        daily_request_budget=None,
        monthly_request_budget=None,
        polling_timeout_seconds=600,
        cache_ttl_days=30,
    )


def test_missing_optional_budgets_default_to_none():
    policy = {
        "quota": {"requests_per_minute": 2, "polling_timeout_seconds": 30, "cache_ttl_days": 1}
    }
    q = parse_quota_policy(policy)
    assert q.per_scan_request_budget is None
    assert q.daily_request_budget is None
    assert q.monthly_request_budget is None
    assert q.requests_per_minute == 2


def test_configured_per_scan_request_budget_parses():
    policy = {
        "quota": {
            "requests_per_minute": 2,
            "per_scan_request_budget": 25,
            "polling_timeout_seconds": 30,
            "cache_ttl_days": 1,
        }
    }
    assert parse_quota_policy(policy).per_scan_request_budget == 25


@pytest.mark.parametrize("value", [0, -1])
def test_parser_rejects_non_positive_required_quota_value(value):
    policy = deepcopy(load_default_policy())
    policy["quota"]["requests_per_minute"] = value
    with pytest.raises(ValueError, match="requests_per_minute"):
        parse_quota_policy(policy)


@pytest.mark.parametrize("value", [0, -1])
def test_parser_rejects_non_positive_optional_quota_budget(value):
    policy = deepcopy(load_default_policy())
    policy["quota"]["per_scan_request_budget"] = value
    with pytest.raises(ValueError, match="per_scan_request_budget"):
        parse_quota_policy(policy)


@pytest.mark.parametrize(
    "field",
    ["requests_per_minute", "polling_timeout_seconds", "cache_ttl_days"],
)
@pytest.mark.parametrize("value", [0, -1])
def test_required_positive_quota_fields_are_validated(field, value):
    policy = deepcopy(load_default_policy())
    policy["quota"][field] = value
    with pytest.raises(ValueError, match=field):
        validate_policy(policy)


@pytest.mark.parametrize(
    "field",
    ["per_scan_request_budget", "daily_request_budget", "monthly_request_budget"],
)
@pytest.mark.parametrize("value", [0, -1])
def test_optional_positive_quota_fields_are_validated(field, value):
    policy = deepcopy(load_default_policy())
    policy["quota"][field] = value
    with pytest.raises(ValueError, match=field):
        validate_policy(policy)
