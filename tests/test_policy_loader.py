from hscanner.policy.loader import load_default_policy


def test_default_policy_has_required_safety_defaults() -> None:
    policy = load_default_policy()

    assert policy["matching"]["default_bucket"] == "hash_only"
    assert policy["matching"]["case_sensitive"] is True
    assert policy["size_limits"]["large_upload_soft_block_mb"] == 200
    assert policy["size_limits"]["absolute_upload_block_mb"] == 650
    assert ".env" in policy["buckets"]["sensitive"]["filename_patterns"]
    assert ".txt" in policy["buckets"]["skipped"]["extensions"]
    assert ".sh" in policy["buckets"]["upload_candidate"]["extensions"]
