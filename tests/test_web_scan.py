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
    assert q.cache_ttl_days == 30


def test_combined_requires_all_keys(tmp_path):
    client = TestClient(create_app(keyring_module=_NoKeys()))

    response = client.post(
        "/scan", data={"folder": str(tmp_path), "engine": "combined"}
    )

    assert response.status_code == 400
    assert "API key is required for:" in response.text


def test_include_subfolders_false_echoed_on_validation_error(tmp_path):
    class _Keys:
        def get_password(self, *args):
            return "KEY"
    client = TestClient(create_app(keyring_module=_Keys()))
    # Non-existent folder forces the validation-error re-render path.
    response = client.post(
        "/scan",
        data={
            "folder": "/does/not/exist",
            "engine": "virustotal",
            "include_subfolders": "false",
        },
    )
    assert response.status_code == 400
    # The checkbox is present and NOT checked: find the input tag that
    # contains name="include_subfolders" and confirm "checked" is absent
    # from that single tag (the guard evaluated false because the value
    # was echoed as False).
    start = response.text.find("<input")
    while start != -1:
        end = response.text.find(">", start)
        tag = response.text[start : end if end != -1 else None]
        if 'name="include_subfolders"' in tag:
            assert "checked" not in tag
            return
        start = response.text.find("<input", end if end != -1 else start + 1)
    raise AssertionError("include_subfolders input not found in response")
