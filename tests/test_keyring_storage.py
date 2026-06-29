from hscanner.keys import clear_saved_api_key, load_saved_api_key, save_api_key


class FakeKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


def test_save_load_and_clear_api_key() -> None:
    fake = FakeKeyring()

    save_api_key("virustotal", "secret", keyring_module=fake)
    assert fake.values == {("HScanner", "virustotal"): "secret"}
    assert load_saved_api_key("virustotal", keyring_module=fake) == "secret"

    clear_saved_api_key("virustotal", keyring_module=fake)
    assert load_saved_api_key("virustotal", keyring_module=fake) is None
