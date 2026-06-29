from fastapi.testclient import TestClient

from hscanner.web.app import create_app


class _FakeKeyring:
    def get_password(self, *a):
        return "KEY"

    def set_password(self, *a):
        pass

    def delete_password(self, *a):
        pass


def test_scan_form_has_no_upload_checkbox_and_has_bypass():
    app = create_app(keyring_module=_FakeKeyring())
    client = TestClient(app)
    html = client.get("/").text
    assert 'name="upload_eligible"' not in html
    assert 'name="bypass_low_risk"' in html


def test_scan_form_offers_engine_choices():
    client = TestClient(create_app())
    body = client.get("/").text
    assert "metadefender" in body and "virustotal" in body and "combined" in body
