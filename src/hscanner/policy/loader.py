from dataclasses import dataclass
from importlib.resources import files
from typing import Any

import yaml


@dataclass(frozen=True)
class QuotaPolicy:
    requests_per_minute: int
    per_scan_request_budget: int | None
    daily_request_budget: int | None
    monthly_request_budget: int | None
    polling_timeout_seconds: int
    cache_ttl_days: int


def parse_quota_policy(policy: dict[str, Any]) -> QuotaPolicy:
    q = policy["quota"]
    parsed = QuotaPolicy(
        requests_per_minute=q["requests_per_minute"],
        per_scan_request_budget=q.get("per_scan_request_budget"),
        daily_request_budget=q.get("daily_request_budget"),
        monthly_request_budget=q.get("monthly_request_budget"),
        polling_timeout_seconds=q["polling_timeout_seconds"],
        cache_ttl_days=q["cache_ttl_days"],
    )
    _validate_quota_policy(parsed)
    return parsed


def _validate_quota_policy(quota: QuotaPolicy) -> None:
    for field in ("requests_per_minute", "polling_timeout_seconds", "cache_ttl_days"):
        if getattr(quota, field) <= 0:
            raise ValueError(f"quota.{field} must be greater than zero")
    for field in (
        "per_scan_request_budget",
        "daily_request_budget",
        "monthly_request_budget",
    ):
        value = getattr(quota, field)
        if value is not None and value <= 0:
            raise ValueError(f"quota.{field} must be null or greater than zero")


def load_default_policy() -> dict[str, Any]:
    policy_path = files("hscanner.policy").joinpath("default_policy.yaml")
    with policy_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    validate_policy(data)
    return data


def validate_policy(policy: dict[str, Any]) -> None:
    required_top_level = {"version", "traversal", "size_limits", "quota", "matching", "buckets"}
    missing = required_top_level - set(policy)
    if missing:
        raise ValueError(f"Policy missing keys: {sorted(missing)}")
    if policy["matching"].get("default_bucket") != "hash_only":
        raise ValueError("Default bucket must be hash_only for the MVP")
    limits = policy["size_limits"]
    if limits["large_upload_soft_block_mb"] >= limits["absolute_upload_block_mb"]:
        raise ValueError("Soft upload block must be below absolute upload block")
    parse_quota_policy(policy)
