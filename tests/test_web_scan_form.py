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
    # All three engines present
    assert "virustotal" in body and "metadefender" in body and "combined" in body
    # Combined card precedes VirusTotal card
    combined_pos = body.find('name="engine" value="combined"')
    virustotal_pos = body.find('name="engine" value="virustotal"')
    assert combined_pos != -1 and virustotal_pos != -1
    assert combined_pos < virustotal_pos


def test_scan_form_default_engine_is_combined():
    client = TestClient(create_app())
    body = client.get("/").text
    # Locate the full <input ...> radio tag for each engine and check `checked`
    import re

    def radio_tag(value: str) -> str:
        m = re.search(
            rf'<input[^>]*\bname="engine"\s+value="{re.escape(value)}"[^>]*>',
            body,
        )
        assert m is not None, f"engine radio for {value!r} not found"
        return m.group(0)

    # Combined radio is checked in the default render (no `engine` context var)
    assert "checked" in radio_tag("combined")
    # VirusTotal radio is NOT checked in the default render
    assert "checked" not in radio_tag("virustotal")
