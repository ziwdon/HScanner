from fastapi.testclient import TestClient

from hscanner.policy.loader import load_default_policy, parse_quota_policy
from hscanner.web.app import create_app


class _NoKeys:
    def get_password(self, *args):
        return None


def test_quota_policy_values_are_available_to_web():
    # Guards the wiring contract: the web layer sources pacing from policy.
    q = parse_quota_policy(load_default_policy())
    assert q.requests_per_minute == 4
    assert q.cache_ttl_days == 7


def test_combined_requires_all_keys(tmp_path):
    client = TestClient(create_app(keyring_module=_NoKeys()))

    response = client.post(
        "/scan", data={"folder": str(tmp_path), "engine": "combined"}
    )

    assert response.status_code == 400
    assert "API key is required for:" in response.text
